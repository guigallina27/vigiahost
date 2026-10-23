package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
)

func openTest(t *testing.T) (*DB, *time.Time) {
	t.Helper()
	ctx := context.Background()
	raw, err := Open(ctx, filepath.Join(t.TempDir(), "teste.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := Migrate(ctx, raw); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	db := New(raw)
	db.Now = func() time.Time { return now }
	return db, &now
}

func insertRun(t *testing.T, db *DB, id string) {
	t.Helper()
	if err := db.InsertRun(context.Background(), &Run{ID: id, Kind: report.KindFiles, Origin: "manual",
		Paths: []string{"/home"}, Incremental: true}); err != nil {
		t.Fatal(err)
	}
}

func webshell(path, sha string) report.Finding {
	return report.Finding{Engine: "yara-x", Signature: "vh_php_upload_direto", Source: "vigiahost",
		Category: report.CategoryWebshell, Severity: report.SeverityHigh, SHA256: sha, FileType: "php",
		Location: &report.Location{Path: path, Size: 120, Mode: 0o644}}
}

var shaA = strings.Repeat("a", 64)

func TestFilaReservaPrioridadeEFinalizacao(t *testing.T) {
	ctx := context.Background()
	db, now := openTest(t)
	insertRun(t, db, "r1")
	*now = now.Add(time.Second)
	if err := db.InsertRun(ctx, &Run{ID: "r2", Kind: report.KindFiles, Origin: "manual", Priority: 5}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertRun(ctx, &Run{ID: "r3", Kind: report.KindFiles, Origin: "manual", IdempotencyKey: "k"}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertRun(ctx, &Run{ID: "r4", Kind: report.KindFiles, Origin: "manual", IdempotencyKey: "k"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("chave de idempotência repetida: %v", err)
	}
	r, err := db.ReserveNext(ctx, report.KindFiles, time.Minute)
	if err != nil || r.ID != "r2" || r.Status != RunReserved || r.Attempts != 1 {
		t.Fatalf("reserva deveria pegar a de maior prioridade: %+v %v", r, err)
	}
	if _, err := db.ReserveNext(ctx, report.KindProcesses, time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fila de processos vazia: %v", err)
	}
	if err := db.MarkRunning(ctx, "r2", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateProgress(ctx, "r2", report.Progress{Phase: "scan", FilesSeen: 10}, false, time.Minute); err != nil {
		t.Fatal(err)
	}
	if n, _ := db.CountActive(ctx, report.KindFiles); n != 1 {
		t.Fatalf("ativas = %d", n)
	}
	sum := &report.Summary{Status: report.StatusCompleted, FilesSeen: 10, Engines: []report.EngineCoverage{
		{Engine: "clamav", Version: "1.4.6", Available: true, Eligible: 10, Analyzed: 10,
			Skipped: map[report.SkipReason]int64{report.SkipTooLarge: 1}}}}
	if err := db.FinishRun(ctx, "r2", string(report.StatusCompleted), sum, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.FinishRun(ctx, "r2", string(report.StatusFailed), nil, "x"); !errors.Is(err, ErrConflict) {
		t.Fatalf("execução final não pode mudar de estado: %v", err)
	}
	got, _ := db.GetRun(ctx, "r2")
	if got.Status != "completed" || got.Summary == nil || got.FilesSeen != 10 || got.FinishedAt == nil {
		t.Fatalf("finalização: %+v", got)
	}
	eng, _ := db.RunEngines(ctx, "r2")
	if len(eng) != 1 || eng[0].Skipped["too_large"] != 1 || !eng[0].Available {
		t.Fatalf("cobertura por motor: %+v", eng)
	}
	if ok, _ := db.CancelQueued(ctx, "r1"); !ok {
		t.Fatal("cancelar execução na fila")
	}
	if ok, _ := db.CancelQueued(ctx, "r2"); ok {
		t.Fatal("execução terminada não volta a ser cancelada")
	}
}

func TestIngestaoIdempotenteCopiasEReabertura(t *testing.T) {
	ctx := context.Background()
	db, now := openTest(t)
	insertRun(t, db, "r1")
	list := []report.Finding{webshell("/home/a/up.php", shaA), webshell("/home/b/up.php", shaA)}
	res, err := db.IngestFindings(ctx, "r1", list, 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.New != 1 || res.Seen != 1 {
		t.Fatalf("duas cópias do mesmo objeto são um achado: %+v", res)
	}
	r, _ := db.GetRun(ctx, "r1")
	if r.FindingsOffset != 100 || r.FindingsCount != 2 {
		t.Fatalf("offset não avançou: %+v", r)
	}
	fs, _ := db.ListFindings(ctx, FindingFilter{})
	if len(fs) != 1 || fs[0].Locations != 2 || fs[0].TimesSeen != 2 {
		t.Fatalf("achado com duas localizações: %+v", fs)
	}
	locs, _ := db.FindingLocations(ctx, shaA)
	if len(locs) != 2 {
		t.Fatalf("localizações: %+v", locs)
	}

	id := fs[0].ID
	if _, err := db.TransitionFinding(ctx, id, StateFalsePositive, "ana", "teste"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.TransitionFinding(ctx, id, StateConfirmed, "ana", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("falso positivo não vai direto a confirmado: %v", err)
	}
	if _, err := db.TransitionFinding(ctx, id, StateNew, "ana", "reabrindo"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.TransitionFinding(ctx, id, StateResolved, "ana", "removido"); err != nil {
		t.Fatal(err)
	}

	*now = now.Add(time.Hour)
	insertRun(t, db, "r2")
	res, err = db.IngestFindings(ctx, "r2", list[:1], 50)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reopened != 1 || len(res.Changed) != 1 {
		t.Fatalf("detectado de novo depois de resolvido deveria reabrir: %+v", res)
	}
	f, _ := db.GetFinding(ctx, id)
	if f.State != StateNew || f.LastRun != "r2" || f.FirstRun != "r1" {
		t.Fatalf("reabertura: %+v", f)
	}
	ev, _ := db.FindingEvents(ctx, id)
	if len(ev) != 5 || ev[len(ev)-1].To != StateNew || ev[len(ev)-1].Actor != "sistema" {
		t.Fatalf("histórico: %+v", ev)
	}
	byRun, _ := db.ListFindings(ctx, FindingFilter{RunID: "r2"})
	if len(byRun) != 1 {
		t.Fatalf("achados da execução r2: %d", len(byRun))
	}
	q, _ := db.ListFindings(ctx, FindingFilter{Query: "b/up"})
	if len(q) != 1 {
		t.Fatalf("busca por caminho: %d", len(q))
	}
}

func TestExcecoesCobremEDeixamDeValer(t *testing.T) {
	ctx := context.Background()
	db, now := openTest(t)
	insertRun(t, db, "r1")
	if _, err := db.IngestFindings(ctx, "r1", []report.Finding{webshell("/home/a/up.php", shaA)}, 10); err != nil {
		t.Fatal(err)
	}
	exp := now.Add(48 * time.Hour)
	e := Exception{Scope: ScopeRulePrefix, Signature: "vh_php_upload_direto", PathPrefix: "/home/a/", Reason: "ferramenta interna",
		CreatedBy: "ana", ExpiresAt: &exp}
	if err := db.CreateException(ctx, &e); err != nil {
		t.Fatal(err)
	}
	fs, _ := db.ListFindings(ctx, FindingFilter{})
	if fs[0].State != StateExcepted || fs[0].ExceptionID == nil || *fs[0].ExceptionID != e.ID {
		t.Fatalf("exceção deveria cobrir o achado aberto: %+v", fs[0])
	}
	// Outro caminho fora do prefixo não é coberto.
	insertRun(t, db, "r2")
	res, _ := db.IngestFindings(ctx, "r2", []report.Finding{webshell("/home/ab/up.php", strings.Repeat("b", 64))}, 10)
	if res.New != 1 {
		t.Fatalf("prefixo não pode cobrir /home/ab: %+v", res)
	}
	// Exceção vencida: o achado volta a "novo" na próxima detecção.
	*now = now.Add(72 * time.Hour)
	insertRun(t, db, "r3")
	res, _ = db.IngestFindings(ctx, "r3", []report.Finding{webshell("/home/a/up.php", shaA)}, 10)
	if res.Reopened != 1 {
		t.Fatalf("exceção vencida deveria reabrir: %+v", res)
	}
	if err := db.RevokeException(ctx, e.ID, "ana"); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeException(ctx, e.ID, "ana"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revogar duas vezes: %v", err)
	}
	all, _ := db.ListExceptions(ctx, true)
	act, _ := db.ListExceptions(ctx, false)
	if len(all) != 1 || len(act) != 0 || all[0].RevokedBy != "ana" {
		t.Fatalf("listagem de exceções: %+v %+v", all, act)
	}
	sev, _ := db.OpenFindingsBySeverity(ctx)
	if sev["high"] != 2 {
		t.Fatalf("abertos por severidade: %+v", sev)
	}
}

func TestFingerprintIndicadorPorLocalizacao(t *testing.T) {
	a := report.Finding{Engine: "inventory", Signature: "nome_extensao_dupla", Category: report.CategoryIndicator,
		SHA256: shaA, Location: &report.Location{Path: "/x/a.php.jpg"}}
	b := a
	b.Location = &report.Location{Path: "/y/a.php.jpg"}
	_, fa := Fingerprint(a)
	_, fb := Fingerprint(b)
	if fa == fb {
		t.Fatal("indicador de nome é por localização, não por conteúdo")
	}
	p := report.Finding{Engine: "inspector", Signature: "exe_apagado", Process: &report.ProcessEvidence{Exe: "/tmp/x"}}
	if k, _ := Fingerprint(p); k != "process" {
		t.Fatalf("tipo = %s", k)
	}
}

func TestAgendamentoDisparaUmaVezEPulaAtrasado(t *testing.T) {
	ctx := context.Background()
	db, now := openTest(t)
	s := Schedule{Name: "diária", Kind: report.KindFiles, Cron: "0 3 * * *", Timezone: "America/Sao_Paulo",
		Paths: []string{"/home"}, Profile: "leve", Enabled: true, MissedPolicy: MissedRunOnce}
	if err := db.SaveSchedule(ctx, &s); err != nil {
		t.Fatal(err)
	}
	// 03:00 em São Paulo = 06:00 UTC do dia seguinte (agora é 12:00 UTC).
	if want := time.Date(2026, 10, 23, 6, 0, 0, 0, time.UTC); s.NextRunAt == nil || !s.NextRunAt.Equal(want) {
		t.Fatalf("próximo horário = %v, esperado %v", s.NextRunAt, want)
	}
	if due, _ := db.DueSchedules(ctx, *now); len(due) != 0 {
		t.Fatal("nada vencido ainda")
	}
	// Core parado por três dias: run_once roda uma vez só.
	*now = time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	due, _ := db.DueSchedules(ctx, *now)
	if len(due) != 1 {
		t.Fatalf("vencidos: %d", len(due))
	}
	fired, err := db.FireSchedule(ctx, due[0], &Run{ID: "s1", Kind: report.KindFiles}, 15*time.Minute)
	if err != nil || !fired {
		t.Fatalf("disparo: %v %v", fired, err)
	}
	if due, _ := db.DueSchedules(ctx, *now); len(due) != 0 {
		t.Fatal("depois do disparo, o próximo horário é futuro")
	}
	// Repetir o mesmo horário (core reiniciou no meio) não duplica.
	if _, err := db.FireSchedule(ctx, due0(due), &Run{ID: "s2", Kind: report.KindFiles}, 0); err != nil {
		t.Fatal(err)
	}
	runs, _ := db.ListRuns(ctx, RunFilter{})
	if len(runs) != 1 || runs[0].Origin != "schedule" || runs[0].ScheduleID == nil {
		t.Fatalf("execuções do agendamento: %+v", runs)
	}

	s.MissedPolicy, s.Cron = MissedSkip, "@hourly"
	if err := db.SaveSchedule(ctx, &s); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(5 * time.Hour)
	due, _ = db.DueSchedules(ctx, *now)
	fired, err = db.FireSchedule(ctx, due[0], &Run{ID: "s3", Kind: report.KindFiles}, 15*time.Minute)
	if err != nil || fired {
		t.Fatalf("skip com atraso não deveria enfileirar: %v %v", fired, err)
	}
	if _, _, err := ParseCron("61 * * * *", "UTC"); err == nil {
		t.Fatal("minuto inválido aceito")
	}
	if _, _, err := ParseCron("@daily", "Lua/Base"); err == nil {
		t.Fatal("fuso inválido aceito")
	}
}

func due0(d []Schedule) Schedule {
	if len(d) > 0 {
		return d[0]
	}
	return Schedule{}
}

func TestPerfisPersonalizados(t *testing.T) {
	ctx := context.Background()
	db, _ := openTest(t)
	if err := db.SaveResourceProfile(ctx, report.Profile{Name: "leve", CPUQuotaPercent: 30}, "ana"); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveResourceProfile(ctx, report.Profile{Name: "leve", CPUQuotaPercent: 40}, "ana"); err != nil {
		t.Fatal(err)
	}
	ps, _ := db.ResourceProfiles(ctx)
	if ps["leve"].Profile.CPUQuotaPercent != 40 {
		t.Fatalf("perfil: %+v", ps)
	}
	_ = db.DeleteResourceProfile(ctx, "leve")
	if ps, _ := db.ResourceProfiles(ctx); len(ps) != 0 {
		t.Fatal("perfil removido")
	}
}

func TestListaDeEstadosFinaisNoSQL(t *testing.T) {
	want := "('" + strings.Join(FinalStatuses, "', '") + "')"
	if finalStatusList != want {
		t.Fatalf("finalStatusList = %s, esperado %s", finalStatusList, want)
	}
}

func TestInstantaneosGuardamOsMaisRecentes(t *testing.T) {
	db, now := openTest(t)
	ctx := context.Background()
	if _, err := db.GetSnapshot(ctx, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sem inspeção: %v", err)
	}
	for i := range SnapshotsKept + 2 {
		id := fmt.Sprintf("p%02d", i)
		insertRun(t, db, id)
		*now = now.Add(time.Minute)
		if err := db.SaveSnapshot(ctx, Snapshot{RunID: id, TakenAt: *now, Processes: []byte(`[{"pid":1}]`),
			Persistence: []byte(`{"baseline":false,"items":[]}`)}); err != nil {
			t.Fatal(err)
		}
	}
	last, err := db.GetSnapshot(ctx, "")
	if err != nil || last.RunID != fmt.Sprintf("p%02d", SnapshotsKept+1) || string(last.Processes) != `[{"pid":1}]` {
		t.Fatalf("mais recente: %+v %v", last, err)
	}
	if _, err := db.GetSnapshot(ctx, "p00"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("o mais antigo devia ter saído: %v", err)
	}
	if _, err := db.GetSnapshot(ctx, "p02"); err != nil {
		t.Fatalf("dentro do limite: %v", err)
	}
}
