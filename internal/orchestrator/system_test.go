package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/store"
)

func systemFinding(subject string) string {
	b, _ := json.Marshal(report.Finding{Engine: "updates", Signature: "atualizacao." + subject, Category: report.CategoryUpdate,
		Severity: report.SeverityMedium, Subject: subject})
	return string(b) + "\n"
}

// Verificações do sistema: tipo próprio na fila, relatório guardado e achados que sumiram resolvidos só quando a
// execução termina completa.
func TestVerificacaoDoSistemaGuardaRelatorioEResolveOQueSumiu(t *testing.T) {
	ctx := context.Background()
	s, fx, now := newService(t)
	if _, err := s.Enqueue(ctx, RunRequest{Kind: report.KindUpdates, Paths: []string{"/etc"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("verificação do sistema com caminhos: %v", err)
	}
	run := func(status report.Status, subjects ...string) string {
		t.Helper()
		r, err := s.Enqueue(ctx, RunRequest{Kind: report.KindUpdates})
		if err != nil {
			t.Fatal(err)
		}
		s.Step(ctx)
		if st := fx.state(r.ID); st == nil {
			t.Fatalf("a execução %s não foi despachada", r.ID)
		}
		for _, sub := range subjects {
			fx.appendFindings(t, r.ID, systemFinding(sub))
		}
		if err := os.WriteFile(filepath.Join(fx.base, r.ID, report.UpdatesFile), []byte(`{"manager":"rpm","security":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		st := fx.state(r.ID)
		st.Active, st.Summary = "inactive", &report.Summary{RunID: r.ID, Kind: report.KindUpdates, Status: status}
		s.Step(ctx)
		got, _ := s.DB.GetRun(ctx, r.ID)
		if got.Status != string(status) {
			t.Fatalf("execução %s: %s", r.ID, got.Status)
		}
		*now = now.Add(time.Minute)
		return r.ID
	}
	first := run(report.StatusCompleted, "security-updates", "reboot")
	if rep, err := s.DB.GetHostReport(ctx, store.HostReportUpdates, ""); err != nil || rep.RunID != first {
		t.Fatalf("relatório: %+v %v", rep, err)
	}
	open := func() []string {
		list, _ := s.DB.ListFindings(ctx, store.FindingFilter{States: store.OpenStates})
		var out []string
		for _, f := range list {
			out = append(out, f.Subject)
		}
		slices.Sort(out)
		return out
	}
	// Parcial não resolve nada: o quadro pode estar incompleto.
	run(report.StatusPartial, "security-updates")
	if got := open(); len(got) != 2 {
		t.Fatalf("parcial resolveu achados: %v", got)
	}
	run(report.StatusCompleted, "security-updates")
	if got := open(); !slices.Equal(got, []string{"security-updates"}) {
		t.Fatalf("reinício pendente deveria estar resolvido: %v", got)
	}
}
