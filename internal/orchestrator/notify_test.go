package orchestrator

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/guigallina27/vigiahost/internal/notify"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/store"
)

// recorder guarda os eventos entregues ao notificador.
type recorder struct {
	mu     sync.Mutex
	events []notify.Event
}

func (r *recorder) Emit(_ context.Context, evs ...notify.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, evs...)
	return nil
}

func (r *recorder) byEvent(name string) []notify.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []notify.Event
	for _, e := range r.events {
		if e.Event == name {
			out = append(out, e)
		}
	}
	return out
}

func TestNotificaAchadosEFimDeExecucao(t *testing.T) {
	ctx := context.Background()
	s, fx, _ := newService(t)
	rec := &recorder{}
	s.Notifier = rec
	r, err := s.Enqueue(ctx, RunRequest{Kind: report.KindFiles, Paths: []string{"/home"}})
	if err != nil {
		t.Fatal(err)
	}
	s.Step(ctx)
	fx.appendFindings(t, r.ID, finding("/home/a/x.php", strings.Repeat("c", 64)), finding("/home/a/y.php", strings.Repeat("d", 64)))
	st := fx.state(r.ID)
	st.Active = "inactive"
	st.Summary = &report.Summary{RunID: r.ID, Status: report.StatusPartial, Engines: []report.EngineCoverage{
		{Engine: "yara-x", Available: true, SelfTest: report.SelfTest{Ran: true, Positive: false, Negative: true}},
		{Engine: "clamav", Available: true, SelfTest: report.SelfTest{Ran: true, Positive: true, Negative: true}},
	}}
	s.Step(ctx)
	found := rec.byEvent(store.EventFindingNew)
	if len(found) != 2 || found[0].Path != "/home/a/x.php" || found[0].RunID != r.ID || found[0].Severity != "high" ||
		!strings.HasPrefix(found[0].Key, "finding:") {
		t.Fatalf("achados novos: %+v", found)
	}
	if p := rec.byEvent(store.EventRunPartial); len(p) != 1 || p[0].RunID != r.ID {
		t.Fatalf("execução parcial: %+v", p)
	}
	if e := rec.byEvent(store.EventEngineSelfTest); len(e) != 1 || e[0].Engine != "yara-x" {
		t.Fatalf("autoteste: %+v", e)
	}

	// Os mesmos achados numa execução seguinte não são novos: nada de notificação repetida.
	r2, _ := s.Enqueue(ctx, RunRequest{Kind: report.KindFiles, Paths: []string{"/home"}})
	s.Step(ctx)
	fx.appendFindings(t, r2.ID, finding("/home/a/x.php", strings.Repeat("c", 64)))
	st2 := fx.state(r2.ID)
	st2.Active, st2.Summary = "inactive", &report.Summary{RunID: r2.ID, Status: report.StatusCompleted}
	s.Step(ctx)
	if n := len(rec.byEvent(store.EventFindingNew)); n != 2 {
		t.Fatalf("achado já conhecido notificou de novo: %d", n)
	}

	// Recusa do executor falha a execução e avisa.
	fx.refuse = "caminho proibido"
	r3, _ := s.Enqueue(ctx, RunRequest{Kind: report.KindFiles, Paths: []string{"/srv"}})
	s.Step(ctx)
	if f := rec.byEvent(store.EventRunFailed); len(f) != 1 || f[0].RunID != r3.ID || !strings.Contains(f[0].Detail, "caminho proibido") {
		t.Fatalf("execução recusada: %+v", f)
	}
}
