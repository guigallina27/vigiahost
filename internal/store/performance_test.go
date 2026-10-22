package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
)

func TestLimitacaoEAjustesDaExecucao(t *testing.T) {
	ctx := context.Background()
	db, now := openTest(t)
	insertRun(t, db, "r1")
	if err := db.RecordAdjustment(ctx, "r1", report.Profile{}, Adjustment{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("ajuste em execução na fila: %v", err)
	}
	if _, err := db.ReserveNext(ctx, report.KindFiles, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkRunning(ctx, "r1", time.Minute); err != nil {
		t.Fatal(err)
	}
	th := &report.ThrottleState{State: report.ThrottlePaused, Workers: 0, Resource: "io", Pressure: 72.5}
	if err := db.UpdateProgress(ctx, "r1", report.Progress{Phase: report.PhaseScanning, Throttle: th}, false, time.Minute); err != nil {
		t.Fatal(err)
	}
	r, _ := db.GetRun(ctx, "r1")
	if r.Throttle == nil || *r.Throttle != *th {
		t.Fatalf("estado da limitação: %+v", r.Throttle)
	}
	if err := db.UpdateProgress(ctx, "r1", report.Progress{Phase: report.PhaseScanning}, false, time.Minute); err != nil {
		t.Fatal(err)
	}
	if r, _ := db.GetRun(ctx, "r1"); r.Throttle != nil {
		t.Fatalf("limitação encerrada continua gravada: %+v", r.Throttle)
	}

	base := report.Profile{Name: "padrao", CPUQuotaPercent: 200, MemoryMaxBytes: 2 << 30, IOWeight: 50, Workers: 2}
	for i := range maxAdjustments + 5 {
		eff := base
		eff.CPUQuotaPercent = 100 + i
		if err := db.RecordAdjustment(ctx, "r1", eff, Adjustment{At: *now, Actor: "admin", Before: LimitsOf(base), After: LimitsOf(eff)}); err != nil {
			t.Fatal(err)
		}
	}
	r, _ = db.GetRun(ctx, "r1")
	if r.Profile.CPUQuotaPercent != 100+maxAdjustments+4 || r.Profile.Workers != 2 {
		t.Fatalf("perfil efetivo: %+v", r.Profile)
	}
	if len(r.Adjustments) != maxAdjustments || r.Adjustments[len(r.Adjustments)-1].After.CPUQuotaPercent != r.Profile.CPUQuotaPercent {
		t.Fatalf("histórico de ajustes: %d", len(r.Adjustments))
	}
	if err := db.FinishRun(ctx, "r1", "completed", &report.Summary{Status: report.StatusCompleted,
		Metrics: &report.Metrics{CPUSeconds: 3.5, Source: "cgroup"}}, ""); err != nil {
		t.Fatal(err)
	}
	if r, _ := db.GetRun(ctx, "r1"); r.Summary == nil || r.Summary.Metrics == nil || r.Summary.Metrics.CPUSeconds != 3.5 {
		t.Fatalf("métricas no resumo: %+v", r.Summary)
	}
	if err := db.RecordAdjustment(ctx, "r1", base, Adjustment{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("ajuste em execução terminada: %v", err)
	}
	if err := db.RecordAdjustment(ctx, "nao-existe", base, Adjustment{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("execução inexistente: %v", err)
	}
}

func TestUltimasExecucoesTerminadasDoTipo(t *testing.T) {
	ctx := context.Background()
	db, now := openTest(t)
	for i := range 5 {
		id := fmt.Sprintf("f%d", i)
		insertRun(t, db, id)
		*now = now.Add(time.Minute)
		if i < 4 {
			if err := db.FinishRun(ctx, id, "completed", nil, ""); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := db.InsertRun(ctx, &Run{ID: "p1", Kind: report.KindProcesses, Origin: "manual"}); err != nil {
		t.Fatal(err)
	}
	_ = db.FinishRun(ctx, "p1", "completed", nil, "")
	list, err := db.RecentFinishedRuns(ctx, report.KindFiles, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || list[0].ID != "f3" || list[2].ID != "f1" {
		ids := []string{}
		for _, r := range list {
			ids = append(ids, r.ID)
		}
		t.Fatalf("últimas terminadas: %v", ids)
	}
}
