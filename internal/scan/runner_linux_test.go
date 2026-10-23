package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/guigallina27/vigiahost/internal/perf"
	"github.com/guigallina27/vigiahost/internal/report"
)

// A varredura pausa entre lotes enquanto a pressão de E/S está alta, retoma quando ela cai, analisa tudo e registra
// os eventos de limitação e as métricas no resumo.
func TestVarreduraLimitadaPorPressao(t *testing.T) {
	root := t.TempDir()
	const total = 300
	for i := range total {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%03d.txt", i)), []byte(fmt.Sprintf("conteúdo %d", i)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	prof := report.Profile{Name: "teste", Workers: 4, ClamdConcurrency: 1, PressureIO: 40}

	// Pressão de E/S em 95% nas primeiras leituras, depois zero.
	var calls atomic.Int64
	pressure := func() perf.Pressure {
		io := 95.0
		if calls.Add(1) > 15 {
			io = 0
		}
		return perf.Pressure{Available: true, IO: perf.PressureStat{Avg10: io}}
	}
	meter := perf.NewMeter(prof, prof.Workers, perf.MeterOptions{Root: fstest.MapFS{}, Pressure: pressure})
	meter.Throttle.Step() // já começa pausada: nenhum lote pode passar antes de a pressão cair

	cfg := Config{Request: report.Request{RunID: "pressao", Kind: report.KindFiles, Paths: []string{root}, Profile: prof},
		OutDir: out, CachePath: filepath.Join(out, "cache.gob"), BatchSize: 10, Meter: meter, SampleInterval: 5 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sum, err := Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if sum.FilesEligible != total {
		t.Fatalf("arquivos elegíveis: %d", sum.FilesEligible)
	}
	var prog report.Progress
	raw, err := os.ReadFile(filepath.Join(out, report.ProgressFile))
	if err == nil {
		err = json.Unmarshal(raw, &prog)
	}
	if err != nil || prog.FilesProcessed != total || prog.Throttle != nil {
		t.Fatalf("progresso final: %+v %v", prog, err)
	}
	m := sum.Metrics
	if m == nil {
		t.Fatal("resumo sem métricas")
	}
	th := m.Throttle
	if !th.Enabled || !th.Available || len(th.Events) < 2 || th.Events[0].Action != report.ThrottleActionPause ||
		th.Events[len(th.Events)-1].Action != report.ThrottleActionRestore || th.PausedSeconds <= 0 || th.LimitedSeconds < th.PausedSeconds {
		t.Fatalf("limitação: %+v", th)
	}
	if th.Events[0].Resource != "io" || th.Events[0].Threshold != 40 {
		t.Fatalf("evento: %+v", th.Events[0])
	}
	phases := map[report.Phase]bool{}
	for _, p := range m.Phases {
		phases[p.Phase] = true
	}
	if !phases[report.PhaseSelfTest] || !phases[report.PhaseScanning] || !phases[report.PhaseLarge] {
		t.Fatalf("etapas: %+v", m.Phases)
	}
	if m.BytesRead <= 0 || m.Source == "" || m.CPUSeconds <= 0 {
		t.Fatalf("consumo: %+v", m)
	}
}
