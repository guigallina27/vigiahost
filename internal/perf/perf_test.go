package perf

import (
	"context"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
)

const cpuPressure = "some avg10=12.50 avg60=8.00 avg300=3.25 total=123456\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"

func TestLeituraDaPressao(t *testing.T) {
	st, err := ParsePressure([]byte(cpuPressure))
	if err != nil || st.Avg10 != 12.5 || st.Avg60 != 8 || st.Avg300 != 3.25 {
		t.Fatalf("pressão: %+v %v", st, err)
	}
	for _, bad := range []string{"", "full avg10=1 avg60=1 avg300=1", "some avg10=x avg60=1 avg300=1", "some avg10=1"} {
		if _, err := ParsePressure([]byte(bad)); err == nil {
			t.Errorf("aceitou %q", bad)
		}
	}
	root := fstest.MapFS{
		"proc/pressure/cpu":    {Data: []byte(cpuPressure)},
		"proc/pressure/io":     {Data: []byte("some avg10=40.00 avg60=20.00 avg300=10.00 total=1\n")},
		"proc/pressure/memory": {Data: []byte("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")},
	}
	p := ReadPressure(root)
	if !p.Available || p.IO.Avg10 != 40 || p.CPU.Avg300 != 3.25 {
		t.Fatalf("leitura: %+v", p)
	}
	delete(root, "proc/pressure/memory")
	if ReadPressure(root).Available {
		t.Fatal("sem o arquivo de memória a pressão não está disponível")
	}
	if v, err := ParseLoadAvg([]byte("0.52 0.80 1.25 2/345 6789\n")); err != nil || v != 1.25 {
		t.Fatalf("loadavg: %v %v", v, err)
	}
}

// clock é um relógio manual para os testes.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestLimitacaoReduzPausaERetoma(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC)}
	sample := Sample{}
	th := NewThrottle(4, Thresholds{CPU: 60, IO: 40}, func() (Sample, bool) { return sample, true }, clk.now)
	step := func(n int) {
		for range n {
			clk.add(time.Second)
			th.Step()
		}
	}
	step(5)
	if th.State() != nil || len(th.Stats().Events) != 0 {
		t.Fatal("sem pressão não deveria limitar")
	}
	// E/S acima do limiar: metade dos workers.
	sample.IO = 45
	step(1)
	st := th.State()
	if st == nil || st.State != report.ThrottleReduced || st.Workers != 2 || st.Resource != "io" {
		t.Fatalf("redução: %+v", st)
	}
	// Ainda acima: espera o intervalo entre mudanças e reduz de novo, até um worker.
	step(1)
	if th.State().Workers != 2 {
		t.Fatal("mudou antes do intervalo mínimo")
	}
	step(3)
	if th.State().Workers != 1 {
		t.Fatalf("segunda redução: %+v", th.State())
	}
	// Com um worker só e a pressão ainda alta, os lotes param.
	step(3)
	if st := th.State(); st.State != report.ThrottlePaused || st.Workers != 0 {
		t.Fatalf("pausa: %+v", st)
	}
	// Pressão entre a retomada (70% do limiar = 28) e o limiar: continua pausada.
	sample.IO = 35
	step(10)
	if th.State().State != report.ThrottlePaused {
		t.Fatal("histerese: não deveria retomar acima de 70% do limiar")
	}
	// Pressão baixa: sobe aos poucos até o paralelismo do perfil.
	sample.IO = 5
	step(30)
	if th.State() != nil {
		t.Fatalf("não voltou ao paralelismo do perfil: %+v", th.State())
	}
	th.Close()
	stats := th.Stats()
	if !stats.Enabled || !stats.Available || stats.LimitedSeconds <= 0 || stats.PausedSeconds <= 0 || stats.PausedSeconds >= stats.LimitedSeconds {
		t.Fatalf("tempos: %+v", stats)
	}
	var actions []string
	for _, e := range stats.Events {
		actions = append(actions, e.Action)
	}
	want := []string{"reduce", "reduce", "pause", "raise", "raise", "restore"}
	if len(actions) != len(want) {
		t.Fatalf("eventos %v, esperado %v", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Fatalf("eventos %v, esperado %v", actions, want)
		}
	}
	if e := stats.Events[0]; e.Resource != "io" || e.Threshold != 40 || e.Pressure != 45 || e.Workers != 2 {
		t.Fatalf("evento: %+v", e)
	}
}

func TestPressaoMuitoAltaPausaDireto(t *testing.T) {
	sample := Sample{CPU: 95}
	th := NewThrottle(8, Thresholds{CPU: 60}, func() (Sample, bool) { return sample, true }, nil)
	th.Step()
	if st := th.State(); st == nil || st.State != report.ThrottlePaused || st.Resource != "cpu" {
		t.Fatalf("acima de 1,5 vez o limiar deveria pausar: %+v", st)
	}
}

func TestSemPSIouSemLimiarNaoLimita(t *testing.T) {
	th := NewThrottle(2, Thresholds{CPU: 10}, func() (Sample, bool) { return Sample{CPU: 99}, false }, nil)
	th.Step()
	if th.State() != nil || th.Stats().Available {
		t.Fatal("PSI ilegível não pode limitar")
	}
	off := NewThrottle(2, Thresholds{}, func() (Sample, bool) { return Sample{CPU: 99}, true }, nil)
	off.Step()
	if off.State() != nil || off.Stats().Enabled {
		t.Fatal("perfil sem limiar não limita")
	}
	var nilThrottle *Throttle
	if err := nilThrottle.Wait(context.Background(), 5); err != nil || nilThrottle.State() != nil {
		t.Fatal("Throttle nil não limita")
	}
}

func TestWorkersEsperamDuranteAPausa(t *testing.T) {
	sample := Sample{IO: 99}
	th := NewThrottle(2, Thresholds{IO: 40}, func() (Sample, bool) { return sample, true }, nil)
	th.Step() // pausa
	ctx := context.Background()
	released := make(chan int, 2)
	for i := range 2 {
		go func() {
			if err := th.Wait(ctx, i); err == nil {
				released <- i
			}
		}()
	}
	select {
	case w := <-released:
		t.Fatalf("worker %d passou durante a pausa", w)
	case <-time.After(100 * time.Millisecond):
	}
	th.Close() // fim da execução libera todos
	for range 2 {
		select {
		case <-released:
		case <-time.After(2 * time.Second):
			t.Fatal("Close não liberou os workers")
		}
	}
	// Contexto cancelado também libera.
	th2 := NewThrottle(1, Thresholds{IO: 40}, func() (Sample, bool) { return sample, true }, nil)
	th2.Step()
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- th2.Wait(cctx, 0) }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("esperava o erro do contexto")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelamento não liberou o worker")
	}
}

func TestEtapasSomamNaOrdem(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	p := NewPhases(clk.now)
	p.Enter(report.PhaseSelfTest)
	clk.add(2 * time.Second)
	p.Enter(report.PhaseScanning)
	clk.add(10 * time.Second)
	p.Enter(report.PhaseLarge)
	clk.add(3 * time.Second)
	p.Enter(report.PhaseDone)
	got := p.Timings()
	if len(got) != 3 || got[0].Phase != report.PhaseSelfTest || got[0].Seconds != 2 || got[1].Seconds != 10 || got[2].Seconds != 3 {
		t.Fatalf("etapas: %+v", got)
	}
}

func TestConsumoPeloCgroupDaUnidade(t *testing.T) {
	unit := "sys/fs/cgroup/vigiahost.slice/vigiahost-run-x.service/"
	root := fstest.MapFS{
		"proc/self/cgroup":         {Data: []byte("0::/vigiahost.slice/vigiahost-run-x.service\n")},
		unit + "cpu.stat":          {Data: []byte("usage_usec 2500000\nuser_usec 2000000\nsystem_usec 500000\n")},
		unit + "memory.current":    {Data: []byte("104857600\n")},
		"proc/pressure/cpu":        {Data: []byte(cpuPressure)},
		"proc/pressure/io":         {Data: []byte(cpuPressure)},
		"proc/pressure/memory":     {Data: []byte(cpuPressure)},
		"sys/fs/cgroup/x/cpu.stat": {Data: []byte("usage_usec 1\n")},
	}
	cg := OwnCgroup(root, []byte("0::/vigiahost.slice/vigiahost-run-x.service\n"))
	if cg == nil {
		t.Fatal("cgroup da unidade não encontrado")
	}
	cg.Sample()
	root[unit+"memory.current"] = &fstest.MapFile{Data: []byte("52428800\n")}
	u, ok := cg.Usage()
	if !ok || u.CPUSeconds != 2.5 || u.MemoryPeakBytes != 100<<20 || u.Source != "cgroup" {
		t.Fatalf("consumo pela amostragem: %+v", u)
	}
	root[unit+"memory.peak"] = &fstest.MapFile{Data: []byte("209715200\n")}
	if u, _ := cg.Usage(); u.MemoryPeakBytes != 200<<20 {
		t.Fatalf("memory.peak: %+v", u)
	}
	// Fora de uma unidade de execução (sessão, outro serviço) os números não são da execução.
	for _, other := range []string{"0::/user.slice/session-1.scope\n", "0::/x\n", "0::/vigiahost.slice/../x/vigiahost-run-y.service\n", ""} {
		if OwnCgroup(root, []byte(other)) != nil {
			t.Errorf("aceitou %q", other)
		}
	}

	m := NewMeter(report.Profile{PressureCPU: 60}, 2, MeterOptions{Root: root})
	if m.Throttle == nil {
		t.Fatal("perfil com limiar deveria criar a limitação")
	}
	stop := m.Start(context.Background(), 10*time.Millisecond)
	m.Phases.Enter(report.PhaseScanning)
	time.Sleep(30 * time.Millisecond)
	stop()
	met := m.Metrics(1 << 30)
	if met.Source != "cgroup" || met.CPUSeconds != 2.5 || met.BytesRead != 1<<30 || !met.Throttle.Available || !met.Throttle.Enabled || len(met.Phases) != 1 {
		t.Fatalf("métricas: %+v", met)
	}
	if NewMeter(report.Profile{}, 2, MeterOptions{Root: root}).Throttle != nil {
		t.Fatal("perfil sem limiar não cria limitação")
	}
}
