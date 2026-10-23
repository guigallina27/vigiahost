package orchestrator

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/perf"
	"github.com/guigallina27/vigiahost/internal/profile"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/store"
)

func TestAjusteEmTempoRealRegistraEfetivoEHistorico(t *testing.T) {
	ctx := context.Background()
	s, fx, _ := newService(t)
	r, _ := s.Enqueue(ctx, RunRequest{Kind: report.KindFiles, Paths: []string{"/a"}})
	cpu := 100
	if _, err := s.Adjust(ctx, r.ID, ipc.RunAdjust{CPUQuotaPercent: &cpu}, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatalf("ajuste antes de rodar: %v", err)
	}
	s.Step(ctx)
	if _, err := s.Adjust(ctx, r.ID, ipc.RunAdjust{}, "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ajuste vazio: %v", err)
	}
	mem := int64(512 << 20)
	got, err := s.Adjust(ctx, r.ID, ipc.RunAdjust{CPUQuotaPercent: &cpu, MemoryMaxBytes: &mem}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if got.Profile.CPUQuotaPercent != 100 || got.Profile.MemoryMaxBytes != mem || got.Profile.Name != r.Profile.Name {
		t.Fatalf("perfil efetivo: %+v", got.Profile)
	}
	if len(got.Adjustments) != 1 || got.Adjustments[0].Actor != "admin" || got.Adjustments[0].Before.CPUQuotaPercent != r.Profile.CPUQuotaPercent ||
		got.Adjustments[0].After.MemoryMaxBytes != mem {
		t.Fatalf("histórico: %+v", got.Adjustments)
	}
	// A recusa das travas vem do executor e não altera nada no banco.
	tooMuch := 400
	var ie *ipc.Error
	if _, err := s.Adjust(ctx, r.ID, ipc.RunAdjust{CPUQuotaPercent: &tooMuch}, "admin"); !errors.As(err, &ie) || ie.Code != ipc.CodeLimitRefused {
		t.Fatalf("trava do executor: %v", err)
	}
	if after, _ := s.DB.GetRun(ctx, r.ID); after.Profile.CPUQuotaPercent != 100 || len(after.Adjustments) != 1 {
		t.Fatalf("recusa alterou o banco: %+v", after.Profile)
	}
	if !slices.Contains(fx.calls, ipc.OpRunAdjust) {
		t.Fatal("ajuste não passou pelo executor")
	}
}

func TestProgressoGuardaALimitacaoPorPressao(t *testing.T) {
	ctx := context.Background()
	s, fx, _ := newService(t)
	r, _ := s.Enqueue(ctx, RunRequest{Kind: report.KindFiles, Paths: []string{"/a"}})
	s.Step(ctx)
	fx.mu.Lock()
	fx.states[r.ID].Progress = &report.Progress{Phase: report.PhaseScanning, FilesProcessed: 10,
		Throttle: &report.ThrottleState{State: report.ThrottleReduced, Workers: 1, Resource: "cpu", Pressure: 70}}
	fx.mu.Unlock()
	s.Step(ctx)
	got, _ := s.DB.GetRun(ctx, r.ID)
	if got.Throttle == nil || got.Throttle.State != report.ThrottleReduced || got.Throttle.Resource != "cpu" {
		t.Fatalf("limitação não gravada: %+v", got.Throttle)
	}
}

func TestSugestaoUsaPressaoEHistorico(t *testing.T) {
	ctx := context.Background()
	s, fx, now := newService(t)
	fx.hw = &ipc.Hardware{CPUs: 8, MemoryBytes: 16 << 30, DiskType: profile.DiskSSD, LoadAvg: 9,
		Pressure: &perf.Pressure{Available: true, CPU: perf.PressureStat{Avg300: 30}, IO: perf.PressureStat{Avg300: 5}}}
	// Duas execuções terminadas: uma de 100 s com 60 s limitada, outra sem métricas (não entra no histórico).
	start := *now
	for i, lim := range []float64{60, -1} {
		run := store.Run{ID: []string{"h1", "h2"}[i], Kind: report.KindFiles, Origin: "manual"}
		if err := s.DB.InsertRun(ctx, &run); err != nil {
			t.Fatal(err)
		}
		sum := &report.Summary{Status: report.StatusCompleted, StartedAt: start, FinishedAt: start.Add(100 * time.Second)}
		if lim >= 0 {
			sum.Metrics = &report.Metrics{Throttle: report.ThrottleStats{LimitedSeconds: lim}}
		}
		if err := s.DB.FinishRun(ctx, run.ID, "completed", sum, ""); err != nil {
			t.Fatal(err)
		}
	}
	sug, hw, load, err := s.Suggest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hw.CPUs != 8 || !load.PSI || load.CPU != 30 || load.Runs != 1 || load.LimitedRatio != 0.6 {
		t.Fatalf("base da sugestão: %+v", load)
	}
	var cs []string
	for _, r := range sug.Reasons {
		cs = append(cs, r.Code)
	}
	if !slices.Contains(cs, "cpu_busy") || !slices.Contains(cs, "history_limited") || sug.Profile.Name != profile.SuggestedName {
		t.Fatalf("sugestão: %v %+v", cs, sug.Profile)
	}
	fx.down = true
	if _, _, _, err := s.Suggest(ctx); !IsUnavailable(err) {
		t.Fatalf("executor fora: %v", err)
	}
}
