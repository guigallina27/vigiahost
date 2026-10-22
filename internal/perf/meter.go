package perf

import (
	"context"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
)

// Meter junta o que uma execução mede: etapas, consumo da unidade e limitação por pressão.
type Meter struct {
	Phases   *Phases
	Throttle *Throttle // nil quando o perfil não liga nenhum limiar
	cgroup   *Cgroup
	psi      bool
}

// MeterOptions permite trocar as fontes nos testes; zero usa o sistema real.
type MeterOptions struct {
	Root fs.FS            // raiz para /proc e /sys (padrão "/")
	Now  func() time.Time // relógio
	// Pressure substitui a leitura de /proc/pressure (testes); nil lê da raiz.
	Pressure func() Pressure
}

// NewMeter prepara a medição para o perfil efetivo da execução, com `workers` workers.
func NewMeter(p report.Profile, workers int, opt MeterOptions) *Meter {
	root := opt.Root
	if root == nil {
		root = os.DirFS("/")
	}
	m := &Meter{Phases: NewPhases(opt.Now)}
	if self, err := fs.ReadFile(root, "proc/self/cgroup"); err == nil {
		m.cgroup = OwnCgroup(root, self)
	}
	read := opt.Pressure
	if read == nil {
		read = func() Pressure { return ReadPressure(root) }
	}
	m.psi = read().Available
	if th := ThresholdsOf(p); th.Enabled() {
		m.Throttle = NewThrottle(workers, th, func() (Sample, bool) { return SampleOf(read()) }, opt.Now)
	}
	return m
}

// Start amostra memória e pressão em segundo plano; a função devolvida para a amostragem e libera os workers.
func (m *Meter) Start(ctx context.Context, interval time.Duration) func() {
	if interval <= 0 {
		interval = time.Second
	}
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() {
		tk := time.NewTicker(interval)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				m.cgroup.Sample()
				m.Throttle.Step()
			}
		}
	})
	return func() {
		cancel()
		wg.Wait()
		m.Throttle.Close()
	}
}

// Metrics monta as medidas finais; bytesRead é o volume lido pela execução.
func (m *Meter) Metrics(bytesRead int64) *report.Metrics {
	out := &report.Metrics{Phases: m.Phases.Timings(), BytesRead: bytesRead}
	if u, ok := m.cgroup.Usage(); ok {
		out.CPUSeconds, out.MemoryPeakBytes, out.Source = u.CPUSeconds, u.MemoryPeakBytes, u.Source
	} else if u := ProcessUsage(); u.Source != "" {
		out.CPUSeconds, out.MemoryPeakBytes, out.Source = u.CPUSeconds, u.MemoryPeakBytes, u.Source
	}
	out.Throttle = m.Throttle.Stats()
	out.Throttle.Available = m.psi
	out.Throttle.Enabled = m.Throttle != nil
	return out
}
