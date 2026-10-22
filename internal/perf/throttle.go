package perf

import (
	"context"
	"sync"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
)

// Thresholds são os limiares de pressão do perfil (avg10, em %); zero desliga o recurso.
type Thresholds struct {
	CPU    int
	IO     int
	Memory int
}

// ThresholdsOf extrai os limiares do perfil.
func ThresholdsOf(p report.Profile) Thresholds {
	return Thresholds{CPU: p.PressureCPU, IO: p.PressureIO, Memory: p.PressureMemory}
}

// Enabled diz se há algum limiar ligado.
func (t Thresholds) Enabled() bool { return t.CPU > 0 || t.IO > 0 || t.Memory > 0 }

// Sample é uma leitura de pressão (avg10 de cada recurso).
type Sample struct {
	CPU    float64
	IO     float64
	Memory float64
}

// SampleOf converte a leitura de /proc/pressure na amostra usada pelo controlador.
func SampleOf(p Pressure) (Sample, bool) {
	return Sample{CPU: p.CPU.Avg10, IO: p.IO.Avg10, Memory: p.Memory.Avg10}, p.Available
}

// Parâmetros do controlador.
const (
	// resumeRatio: a pressão precisa cair abaixo de 70% do limiar para o ritmo voltar a subir (histerese).
	resumeRatio = 0.7
	// pauseRatio: acima de 1,5 vez o limiar (ou já com um worker só), os lotes param.
	pauseRatio = 1.5
	// hold: amostras entre duas mudanças de ritmo. O avg10 do kernel reage devagar; mudar a cada segundo
	// derrubaria o paralelismo antes de a medida refletir a mudança anterior.
	hold = 3
	// maxEvents guarda os primeiros eventos; os demais só são contados.
	maxEvents = 200
)

// Throttle reduz o paralelismo e pausa entre lotes quando a pressão do servidor passa dos limiares do perfil, e
// retoma quando ela cai. Os workers chamam Wait antes de cada lote; o worker de índice i só segue enquanto
// i < workers liberados. Um Throttle nil não limita nada.
type Throttle struct {
	max  int
	th   Thresholds
	read func() (Sample, bool)
	now  func() time.Time

	mu        sync.Mutex
	cond      *sync.Cond
	allowed   int
	cooldown  int
	calm      int
	closed    bool
	available bool
	sampled   bool
	since     time.Time // início do trecho limitado atual (allowed < max)
	pausedAt  time.Time // início do trecho pausado atual (allowed == 0)
	limited   time.Duration
	paused    time.Duration
	events    []report.ThrottleEvent
	dropped   int
	current   *report.ThrottleState
}

// NewThrottle cria o controlador para `workers` workers. read devolve a pressão atual e se ela está disponível;
// now é o relógio (nil usa time.Now).
func NewThrottle(workers int, th Thresholds, read func() (Sample, bool), now func() time.Time) *Throttle {
	if now == nil {
		now = time.Now
	}
	t := &Throttle{max: max(workers, 1), th: th, read: read, now: now, allowed: max(workers, 1)}
	t.cond = sync.NewCond(&t.mu)
	return t
}

// Step avalia uma amostra e ajusta o paralelismo.
func (t *Throttle) Step() {
	if t == nil || !t.th.Enabled() {
		return
	}
	s, ok := t.read()
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.sampled {
		t.sampled, t.available = true, ok
	}
	if !ok || t.closed {
		return
	}
	t.available = true
	resource, value, threshold, ratio := t.worst(s)
	if t.cooldown > 0 {
		t.cooldown--
	}
	switch {
	case ratio >= 1:
		t.calm = 0
		if t.cooldown > 0 || t.allowed == 0 {
			t.updateCurrent(resource, value)
			return
		}
		if ratio >= pauseRatio || t.allowed <= 1 {
			t.set(0, report.ThrottleActionPause, resource, value, threshold)
		} else {
			t.set(max(1, t.allowed/2), report.ThrottleActionReduce, resource, value, threshold)
		}
	case ratio < resumeRatio:
		t.calm++
		if t.allowed >= t.max || t.cooldown > 0 || t.calm < hold {
			if t.allowed < t.max {
				t.updateCurrent(resource, value)
			}
			return
		}
		next := min(t.max, max(1, t.allowed*2))
		action := report.ThrottleActionRaise
		if next == t.max {
			action = report.ThrottleActionRestore
		}
		t.set(next, action, resource, value, threshold)
		t.calm = 0
	default:
		// Entre a retomada e o limiar: mantém o ritmo atual.
		t.calm = 0
		if t.allowed < t.max {
			t.updateCurrent(resource, value)
		}
	}
}

// worst escolhe o recurso mais pressionado em relação ao próprio limiar.
func (t *Throttle) worst(s Sample) (resource string, value float64, threshold int, ratio float64) {
	for _, r := range []struct {
		name string
		v    float64
		th   int
	}{{"cpu", s.CPU, t.th.CPU}, {"io", s.IO, t.th.IO}, {"memory", s.Memory, t.th.Memory}} {
		if r.th <= 0 {
			continue
		}
		if q := r.v / float64(r.th); resource == "" || q > ratio {
			resource, value, threshold, ratio = r.name, r.v, r.th, q
		}
	}
	return resource, value, threshold, ratio
}

// set muda o paralelismo liberado, contabiliza o tempo limitado e registra o evento. Chamado com mu travado.
func (t *Throttle) set(allowed int, action, resource string, value float64, threshold int) {
	now := t.now()
	if t.allowed == t.max && allowed < t.max {
		t.since = now
	}
	if t.allowed > 0 && allowed == 0 {
		t.pausedAt = now
	}
	if t.allowed == 0 && allowed > 0 {
		t.paused += now.Sub(t.pausedAt)
	}
	if t.allowed < t.max && allowed == t.max {
		t.limited += now.Sub(t.since)
	}
	t.allowed = allowed
	t.cooldown = hold
	if len(t.events) < maxEvents {
		t.events = append(t.events, report.ThrottleEvent{At: now.UTC(), Action: action, Resource: resource,
			Pressure: round1(value), Threshold: threshold, Workers: allowed})
	} else {
		t.dropped++
	}
	t.updateCurrent(resource, value)
	t.cond.Broadcast()
}

func (t *Throttle) updateCurrent(resource string, value float64) {
	if t.allowed >= t.max {
		t.current = nil
		return
	}
	state := report.ThrottleReduced
	if t.allowed == 0 {
		state = report.ThrottlePaused
	}
	t.current = &report.ThrottleState{State: state, Workers: t.allowed, Resource: resource, Pressure: round1(value)}
}

// Wait bloqueia o worker de índice `worker` enquanto ele estiver acima do paralelismo liberado. Devolve o erro do
// contexto se ele acabar antes.
func (t *Throttle) Wait(ctx context.Context, worker int) error {
	if t == nil {
		return ctx.Err()
	}
	stop := context.AfterFunc(ctx, func() {
		t.mu.Lock()
		t.cond.Broadcast()
		t.mu.Unlock()
	})
	defer stop()
	t.mu.Lock()
	defer t.mu.Unlock()
	for worker >= t.allowed && !t.closed {
		if err := ctx.Err(); err != nil {
			return err
		}
		t.cond.Wait()
	}
	return ctx.Err()
}

// Close libera todos os workers (fim da execução) e fecha a contagem de tempo.
func (t *Throttle) Close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	now := t.now()
	if t.allowed == 0 {
		t.paused += now.Sub(t.pausedAt)
	}
	if t.allowed < t.max {
		t.limited += now.Sub(t.since)
	}
	t.closed, t.current = true, nil
	t.cond.Broadcast()
}

// State devolve a limitação em andamento (nil sem limitação).
func (t *Throttle) State() *report.ThrottleState {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current == nil {
		return nil
	}
	c := *t.current
	return &c
}

// Stats resume a limitação. Chame depois de Close para ter os tempos completos.
func (t *Throttle) Stats() report.ThrottleStats {
	if t == nil {
		return report.ThrottleStats{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return report.ThrottleStats{Available: t.available, Enabled: t.th.Enabled(), LimitedSeconds: t.limited.Seconds(),
		PausedSeconds: t.paused.Seconds(), Events: append([]report.ThrottleEvent(nil), t.events...), EventsDropped: t.dropped}
}

func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}
