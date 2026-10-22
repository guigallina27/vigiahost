package perf

import (
	"sync"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
)

// Phases cronometra as etapas da execução, na ordem em que aconteceram. Etapa repetida soma no mesmo item.
type Phases struct {
	now   func() time.Time
	mu    sync.Mutex
	cur   report.Phase
	start time.Time
	out   []report.PhaseTiming
}

// NewPhases cria o cronômetro; now nil usa time.Now.
func NewPhases(now func() time.Time) *Phases {
	if now == nil {
		now = time.Now
	}
	return &Phases{now: now}
}

// Enter fecha a etapa corrente e começa a próxima. PhaseDone só fecha.
func (p *Phases) Enter(ph report.Phase) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.closeLocked(now)
	if ph == report.PhaseDone {
		p.cur = ""
		return
	}
	p.cur, p.start = ph, now
}

func (p *Phases) closeLocked(now time.Time) {
	if p.cur == "" {
		return
	}
	secs := now.Sub(p.start).Seconds()
	for i := range p.out {
		if p.out[i].Phase == p.cur {
			p.out[i].Seconds += secs
			p.cur = ""
			return
		}
	}
	p.out = append(p.out, report.PhaseTiming{Phase: p.cur, Seconds: secs})
	p.cur = ""
}

// Timings fecha a etapa corrente e devolve as durações.
func (p *Phases) Timings() []report.PhaseTiming {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked(p.now())
	out := make([]report.PhaseTiming, len(p.out))
	copy(out, p.out)
	return out
}
