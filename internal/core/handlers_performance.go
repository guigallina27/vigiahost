package core

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/perf"
	"github.com/guigallina27/vigiahost/internal/profile"
	"github.com/guigallina27/vigiahost/internal/store"
)

// AdjustRunLimits muda CPU, memória e E/S da execução em andamento. A rota exige administrador com reautenticação;
// as travas ficam no executor, que recebe só os campos pedidos e decide sobre o perfil efetivo que ele guarda.
func (s *Server) AdjustRunLimits(w http.ResponseWriter, r *http.Request, runID api.RunId) {
	var in api.RunAdjustRequest
	if !decode(w, r, &in) {
		return
	}
	adj := ipc.RunAdjust{RunID: runID, CPUQuotaPercent: in.CpuQuotaPercent, MemoryMaxBytes: in.MemoryMaxBytes,
		IOReadBytesPerSec: in.IoReadBytesPerSec, IOWeight: in.IoWeight, NoReserve: in.NoReserve != nil && *in.NoReserve}
	bad := func(msg string) { writeError(w, http.StatusBadRequest, msg, "bad_request") }
	switch {
	case adj.Empty():
		bad("informe ao menos um limite para ajustar")
		return
	case adj.CPUQuotaPercent != nil && *adj.CPUQuotaPercent < 0,
		adj.MemoryMaxBytes != nil && *adj.MemoryMaxBytes < 0,
		adj.IOReadBytesPerSec != nil && *adj.IOReadBytesPerSec < 0:
		bad("limites não podem ser negativos")
		return
	case adj.IOWeight != nil && (*adj.IOWeight < 1 || *adj.IOWeight > 10000):
		bad("peso de E/S deve ficar entre 1 e 10000")
		return
	}
	before, err := s.DB.GetRun(r.Context(), runID)
	if err != nil {
		s.storeError(w, err)
		return
	}
	run, err := s.Orch.Adjust(r.Context(), runID, adj, principalFrom(r.Context()).Actor())
	if err != nil {
		s.storeError(w, err)
		return
	}
	detail := describeAdjustment(store.LimitsOf(before.Profile), store.LimitsOf(run.Profile))
	if adj.NoReserve {
		detail += " (pedido sem reserva do sistema)"
	}
	s.audit(r, "run_limits_adjusted", runID, detail)
	writeJSON(w, http.StatusOK, toAPIRun(run))
}

// describeAdjustment resume o que mudou para a auditoria ("cpu 200% → 100%; memória 2048 MiB → 1024 MiB").
func describeAdjustment(a, b store.Limits) string {
	var parts []string
	if a.CPUQuotaPercent != b.CPUQuotaPercent {
		parts = append(parts, fmt.Sprintf("cpu %d%% → %d%%", a.CPUQuotaPercent, b.CPUQuotaPercent))
	}
	if a.MemoryMaxBytes != b.MemoryMaxBytes {
		parts = append(parts, fmt.Sprintf("memória %d MiB → %d MiB", a.MemoryMaxBytes>>20, b.MemoryMaxBytes>>20))
	}
	if a.IOReadBytesPerSec != b.IOReadBytesPerSec {
		parts = append(parts, fmt.Sprintf("leitura %d MiB/s → %d MiB/s", a.IOReadBytesPerSec>>20, b.IOReadBytesPerSec>>20))
	}
	if a.IOWeight != b.IOWeight {
		parts = append(parts, fmt.Sprintf("peso de E/S %d → %d", a.IOWeight, b.IOWeight))
	}
	if len(parts) == 0 {
		return "sem mudança efetiva"
	}
	return strings.Join(parts, "; ")
}

// GetRunComparison devolve o desempenho da execução ao lado das últimas terminadas do mesmo tipo.
func (s *Server) GetRunComparison(w http.ResponseWriter, r *http.Request, runID api.RunId, params api.GetRunComparisonParams) {
	limit := 10
	if params.Limit != nil {
		limit = max(2, min(30, *params.Limit))
	}
	cur, err := s.DB.GetRun(r.Context(), runID)
	if err != nil {
		s.storeError(w, err)
		return
	}
	recent, err := s.DB.RecentFinishedRuns(r.Context(), cur.Kind, limit)
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := api.RunComparison{Kind: api.RunKind(cur.Kind), Runs: make([]api.RunPerformance, 0, len(recent)+1)}
	seen := false
	for _, run := range recent {
		seen = seen || run.ID == cur.ID
	}
	if !seen {
		// Execução em andamento (ou mais antiga que as últimas N): entra na frente para servir de referência.
		out.Runs = append(out.Runs, toAPIPerformance(cur, true))
		if len(recent) >= limit {
			recent = recent[:limit-1]
		}
	}
	for _, run := range recent {
		out.Runs = append(out.Runs, toAPIPerformance(run, run.ID == cur.ID))
	}
	writeJSON(w, http.StatusOK, out)
}

func toAPIPerformance(r store.Run, current bool) api.RunPerformance {
	out := api.RunPerformance{Id: r.ID, Status: api.RunStatus(r.Status), Profile: r.Profile.Name, CreatedAt: r.CreatedAt,
		FinishedAt: optTime(r.FinishedAt), FilesEligible: r.FilesEligible, BytesEligible: r.BytesEligible,
		Findings: r.FindingsCount, Current: current}
	if sm := r.Summary; sm != nil {
		if d := sm.FinishedAt.Sub(sm.StartedAt).Seconds(); d > 0 {
			out.DurationSeconds = float32(d)
		}
		out.FilesPerSecond, out.MbPerSecond = float32(sm.FilesPerSecond), float32(sm.MBPerSecond)
		out.CacheHits, out.Findings = sm.CacheHits, sm.Findings
		if m := sm.Metrics; m != nil {
			out.CpuSeconds = ptr(float32(m.CPUSeconds))
			out.MemoryPeakBytes = ptr(m.MemoryPeakBytes)
			out.LimitedSeconds = ptr(float32(m.Throttle.LimitedSeconds))
		}
	} else if r.StartedAt != nil {
		// Em andamento: duração até agora pelo último batimento.
		end := r.StartedAt
		if r.HeartbeatAt != nil {
			end = r.HeartbeatAt
		}
		out.DurationSeconds = float32(end.Sub(*r.StartedAt).Seconds())
	}
	return out
}

// GetResourceSuggestion calcula o perfil sugerido com a explicação de cada limite.
func (s *Server) GetResourceSuggestion(w http.ResponseWriter, r *http.Request) {
	sug, hw, load, err := s.Orch.Suggest(r.Context())
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := api.ProfileSuggestion{Profile: toAPIProfile(sug.Profile), Reasons: make([]api.SuggestionReason, 0, len(sug.Reasons)),
		Basis: api.SuggestionBasis{Cpus: hw.CPUs, MemoryBytes: hw.MemoryBytes,
			DiskType: api.DiskType(profile.Hardware{Rotational: hw.Rotational, DiskType: hw.DiskType}.Disk()),
			Psi:      load.PSI, CpuPressure: float32(load.CPU), IoPressure: float32(load.IO), MemoryPressure: float32(load.Memory),
			LoadAvg: float32(load.LoadAvg), HistoryRuns: load.Runs, LimitedRatio: float32(load.LimitedRatio)}}
	for _, rs := range sug.Reasons {
		vals := make(map[string]float32, len(rs.Values))
		for k, v := range rs.Values {
			vals[k] = float32(v)
		}
		out.Reasons = append(out.Reasons, api.SuggestionReason{Code: api.SuggestionReasonCode(rs.Code), Values: vals})
	}
	writeJSON(w, http.StatusOK, out)
}

func toAPIPressure(p perf.PressureStat) api.PressureStat {
	return api.PressureStat{Avg10: float32(p.Avg10), Avg60: float32(p.Avg60), Avg300: float32(p.Avg300)}
}
