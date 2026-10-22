package core

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/store"
)

func TestAjusteComparativoESugestaoPelaAPI(t *testing.T) {
	a := newTestAPI(t)
	ctx := context.Background()
	admin := a.sessionFor(t, store.RoleAdmin, true)
	operator := a.sessionFor(t, store.RoleOperator, true)

	rec := a.do(t, "POST", "/api/v1/runs", `{"kind":"files","paths":["/home"],"profile":"leve"}`, admin, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("criar execução: %d %s", rec.Code, rec.Body.String())
	}
	run := decodeBody[api.Run](t, rec)

	// Na fila ainda não há unidade para ajustar.
	if rec := a.do(t, "POST", "/api/v1/runs/"+run.Id+"/adjust", `{"cpu_quota_percent":100}`, admin, ""); rec.Code != http.StatusConflict {
		t.Fatalf("ajuste na fila: %d %s", rec.Code, rec.Body.String())
	}
	a.srv.Orch.Step(ctx)

	// Operador não ajusta limites; administrador precisa de reautenticação (matriz) e de ao menos um campo.
	if rec := a.do(t, "POST", "/api/v1/runs/"+run.Id+"/adjust", `{"cpu_quota_percent":100}`, operator, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("operador ajustando: %d", rec.Code)
	}
	for _, body := range []string{`{}`, `{"cpu_quota_percent":-1}`, `{"io_weight":0}`, `{"workers":8}`} {
		if rec := a.do(t, "POST", "/api/v1/runs/"+run.Id+"/adjust", body, admin, ""); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", body, rec.Code, rec.Body.String())
		}
	}
	// Recusa das travas do executor chega como 400 com o código limit_refused.
	rec = a.do(t, "POST", "/api/v1/runs/"+run.Id+"/adjust", `{"cpu_quota_percent":400,"no_reserve":true}`, admin, "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "limit_refused") {
		t.Fatalf("trava: %d %s", rec.Code, rec.Body.String())
	}
	rec = a.do(t, "POST", "/api/v1/runs/"+run.Id+"/adjust", `{"cpu_quota_percent":75,"memory_max_bytes":536870912}`, admin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("ajuste: %d %s", rec.Code, rec.Body.String())
	}
	adjusted := decodeBody[api.Run](t, rec)
	if adjusted.Profile.CpuQuotaPercent != 75 || adjusted.Profile.MemoryMaxBytes != 512<<20 || adjusted.Adjustments == nil ||
		len(*adjusted.Adjustments) != 1 || (*adjusted.Adjustments)[0].Actor != "u-admin" {
		t.Fatalf("execução ajustada: %+v %+v", adjusted.Profile, adjusted.Adjustments)
	}
	audit := decodeBody[api.AuditPage](t, a.do(t, "GET", "/api/v1/audit", "", admin, ""))
	found := false
	for _, e := range audit.Entries {
		if e.Action == "run_limits_adjusted" && e.Target == run.Id && strings.Contains(e.Detail, "cpu") && strings.Contains(e.Detail, "50% → 75%") {
			found = true
		}
	}
	if !found {
		t.Fatal("ajuste sem auditoria")
	}

	// Execução terminada com métricas: o detalhe traz as métricas e a vazão por motor; o comparativo junta as últimas.
	*a.now = a.now.Add(time.Minute)
	sum := &report.Summary{Status: report.StatusCompleted, StartedAt: a.now.Add(-50 * time.Second), FinishedAt: *a.now,
		FilesEligible: 100, FilesPerSecond: 2, MBPerSecond: 1.5,
		Engines: []report.EngineCoverage{{Engine: "yara-x", Analyzed: 90, FromCache: 10, BytesAnalyzed: 80 << 20, Seconds: 8}},
		Metrics: &report.Metrics{CPUSeconds: 12, MemoryPeakBytes: 300 << 20, BytesRead: 2 << 30, Source: "cgroup",
			Phases: []report.PhaseTiming{{Phase: report.PhaseScanning, Seconds: 45}},
			Throttle: report.ThrottleStats{Available: true, Enabled: true, LimitedSeconds: 12, PausedSeconds: 4,
				Events: []report.ThrottleEvent{{At: *a.now, Action: report.ThrottleActionPause, Resource: "io", Pressure: 70, Threshold: 40}}}}}
	if err := a.db.FinishRun(ctx, run.Id, "completed", sum, ""); err != nil {
		t.Fatal(err)
	}
	detail := decodeBody[api.RunDetail](t, a.do(t, "GET", "/api/v1/runs/"+run.Id, "", operator, ""))
	m := detail.Run.Summary.Metrics
	if m == nil || m.Source != api.RunMetricsSourceCgroup || m.CpuSecondsPerGb == nil || *m.CpuSecondsPerGb != 6 || len(m.Throttle.Events) != 1 {
		t.Fatalf("métricas no detalhe: %+v", m)
	}
	if e := detail.Engines[0]; e.FilesPerSecond == nil || *e.FilesPerSecond != 10 || e.MbPerSecond == nil || *e.MbPerSecond != 10 {
		t.Fatalf("vazão por motor: %+v", e)
	}
	if rec := a.do(t, "POST", "/api/v1/runs/"+run.Id+"/adjust", `{"cpu_quota_percent":100}`, admin, ""); rec.Code != http.StatusConflict {
		t.Fatalf("ajuste em execução terminada: %d", rec.Code)
	}

	second := decodeBody[api.Run](t, a.do(t, "POST", "/api/v1/runs", `{"kind":"files","paths":["/srv"]}`, admin, ""))
	cmp := decodeBody[api.RunComparison](t, a.do(t, "GET", "/api/v1/runs/"+second.Id+"/comparison?limit=5", "", operator, ""))
	if cmp.Kind != api.Files || len(cmp.Runs) != 2 || !cmp.Runs[0].Current || cmp.Runs[0].Id != second.Id ||
		cmp.Runs[1].Id != run.Id || cmp.Runs[1].CpuSeconds == nil || *cmp.Runs[1].LimitedSeconds != 12 || cmp.Runs[1].DurationSeconds != 50 {
		t.Fatalf("comparativo: %+v", cmp.Runs)
	}
	if rec := a.do(t, "GET", "/api/v1/runs/nao-existe/comparison", "", operator, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("comparativo de execução inexistente: %d", rec.Code)
	}

	sug := decodeBody[api.ProfileSuggestion](t, a.do(t, "GET", "/api/v1/resources/suggestion", "", operator, ""))
	if sug.Profile.Name != "sugerido" || sug.Basis.Cpus != 4 || sug.Basis.DiskType != api.Ssd || !sug.Basis.Psi ||
		sug.Basis.HistoryRuns != 1 || len(sug.Reasons) < 4 || sug.Profile.PressureCpu == nil {
		t.Fatalf("sugestão: %+v", sug)
	}
	res := decodeBody[api.Resources](t, a.do(t, "GET", "/api/v1/resources", "", operator, ""))
	if res.Hardware.DiskType == nil || *res.Hardware.DiskType != api.Ssd || res.Hardware.Pressure == nil ||
		res.Profiles[0].Profile.PressureIo == nil || *res.Profiles[0].Profile.PressureIo == 0 {
		t.Fatalf("recursos com disco, pressão e limiares: %+v", res.Hardware)
	}
	// "Aplicar sugestão" grava o perfil próprio pela rota de perfis (administrador com reautenticação).
	body := `{"name":"sugerido","cpu_quota_percent":200,"memory_max_bytes":1073741824,"io_read_bytes_per_sec":0,"io_weight":50,` +
		`"workers":2,"clamd_concurrency":2,"max_runtime_sec":43200,"nice":10,"max_file_bytes":0,"pressure_cpu":50,"pressure_io":40,"pressure_memory":20}`
	res = decodeBody[api.Resources](t, a.do(t, "PUT", "/api/v1/resources/profiles/sugerido", body, admin, ""))
	ok := false
	for _, p := range res.Profiles {
		if p.Profile.Name == "sugerido" && p.Custom && *p.Profile.PressureIo == 40 {
			ok = true
		}
	}
	if !ok {
		t.Fatal("perfil sugerido não gravado com os limiares")
	}
	bad := strings.Replace(body, `"pressure_io":40`, `"pressure_io":150`, 1)
	if rec := a.do(t, "PUT", "/api/v1/resources/profiles/sugerido", bad, admin, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("limiar acima de 100%%: %d", rec.Code)
	}
}

func TestDescricaoDoAjusteNaAuditoria(t *testing.T) {
	a := store.Limits{CPUQuotaPercent: 200, MemoryMaxBytes: 2 << 30, IOReadBytesPerSec: 0, IOWeight: 50}
	b := store.Limits{CPUQuotaPercent: 100, MemoryMaxBytes: 1 << 30, IOReadBytesPerSec: 10 << 20, IOWeight: 20}
	got := describeAdjustment(a, b)
	for _, want := range []string{"cpu 200% → 100%", "memória 2048 MiB → 1024 MiB", "leitura 0 MiB/s → 10 MiB/s", "peso de E/S 50 → 20"} {
		if !strings.Contains(got, want) {
			t.Errorf("faltou %q em %q", want, got)
		}
	}
	if describeAdjustment(a, a) != "sem mudança efetiva" {
		t.Fatal("ajuste sem mudança")
	}
}
