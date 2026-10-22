package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/store"
)

// fakeExec simula o executor: cada execução iniciada ganha um diretório e um estado controlado pelo teste.
type fakeExec struct {
	mu      sync.Mutex
	base    string
	down    bool
	refuse  string
	states  map[string]*ipc.RunState
	started []report.Request
	calls   []ipc.Op
}

func newFake(t *testing.T) *fakeExec {
	return &fakeExec{base: t.TempDir(), states: map[string]*ipc.RunState{}}
}

func (f *fakeExec) Call(_ context.Context, op ipc.Op, in, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, op)
	if f.down {
		return &Unavailable{Err: errors.New("connection refused")}
	}
	set := func(v any) {
		if out != nil {
			b, _ := json.Marshal(v)
			_ = json.Unmarshal(b, out)
		}
	}
	switch op {
	case ipc.OpHardware:
		set(ipc.Hardware{CPUs: 4, MemoryBytes: 8 << 30})
	case ipc.OpRunStart:
		req := in.(ipc.RunStart).Request
		if f.refuse != "" {
			return &ipc.Error{Code: ipc.CodePathRefused, Message: f.refuse}
		}
		dir := filepath.Join(f.base, req.RunID)
		_ = os.MkdirAll(dir, 0o755)
		st := &ipc.RunState{RunID: req.RunID, Dir: dir, Active: "active", Sub: "running"}
		f.states[req.RunID] = st
		f.started = append(f.started, req)
		set(st)
	case ipc.OpRunStatus, ipc.OpRunCancel, ipc.OpRunPause, ipc.OpRunResume:
		id := in.(ipc.RunRef).RunID
		st, ok := f.states[id]
		if !ok {
			return &ipc.Error{Code: ipc.CodeNotFound, Message: "execução desconhecida"}
		}
		switch op {
		case ipc.OpRunCancel:
			st.Active, st.Result = "inactive", "success"
		case ipc.OpRunPause:
			st.Frozen = true
		case ipc.OpRunResume:
			st.Frozen = false
		}
		set(st)
	case ipc.OpRunLimits:
		set(f.states[in.(ipc.RunLimits).RunID])
	case ipc.OpRunList:
		var l ipc.RunList
		for _, st := range f.states {
			l.Runs = append(l.Runs, *st)
		}
		set(l)
	case ipc.OpRunCleanup:
		delete(f.states, in.(ipc.RunRef).RunID)
	default:
		return &ipc.Error{Code: ipc.CodeUnsupportedOp, Message: string(op)}
	}
	return nil
}

func (f *fakeExec) state(id string) *ipc.RunState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.states[id]
}

func (f *fakeExec) appendFindings(t *testing.T, id string, lines ...string) {
	t.Helper()
	fh, err := os.OpenFile(filepath.Join(f.base, id, report.FindingsFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	for _, l := range lines {
		if _, err := io.WriteString(fh, l); err != nil {
			t.Fatal(err)
		}
	}
}

func finding(path, sha string) string {
	b, _ := json.Marshal(report.Finding{Engine: "clamav", Signature: "Php.Webshell.X", Category: report.CategoryWebshell,
		Severity: report.SeverityHigh, SHA256: sha, Location: &report.Location{Path: path}})
	return string(b) + "\n"
}

func newService(t *testing.T) (*Service, *fakeExec, *time.Time) {
	t.Helper()
	ctx := context.Background()
	raw, err := store.Open(ctx, filepath.Join(t.TempDir(), "core.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := store.Migrate(ctx, raw); err != nil {
		t.Fatal(err)
	}
	db := store.New(raw)
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	db.Now = func() time.Time { return now }
	fx := newFake(t)
	s := &Service{DB: db, Exec: fx, Hub: NewHub(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return s, fx, &now
}

func TestCicloCompletoComIngestaoIncremental(t *testing.T) {
	ctx := context.Background()
	s, fx, _ := newService(t)
	events, cancel := s.Hub.Subscribe()
	defer cancel()

	r, err := s.Enqueue(ctx, RunRequest{Kind: report.KindFiles, Paths: []string{"/home/", "/home", "/var/www/../www"},
		Profile: "leve", RequestedBy: "ana", IdempotencyKey: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.Paths, ",") != "/home,/var/www" || r.Profile.Name != "leve" || r.Profile.CPUQuotaPercent == 0 {
		t.Fatalf("pedido normalizado: %+v", r)
	}
	again, err := s.Enqueue(ctx, RunRequest{Kind: report.KindFiles, Paths: []string{"/home"}, IdempotencyKey: "abc"})
	if err != nil || again.ID != r.ID {
		t.Fatalf("mesma chave deveria devolver a mesma execução: %v %v", again.ID, err)
	}

	s.Step(ctx)
	got, _ := s.DB.GetRun(ctx, r.ID)
	if got.Status != store.RunRunning || len(fx.started) != 1 {
		t.Fatalf("execução deveria estar rodando: %+v", got)
	}
	// Achado completo + linha parcial (ainda sendo escrita) + linha inválida.
	fx.appendFindings(t, r.ID, finding("/home/a/x.php", strings.Repeat("c", 64)), "{lixo}\n", `{"engine":"clamav"`)
	fx.state(r.ID).Progress = &report.Progress{Phase: "scan", FilesSeen: 5, FilesProcessed: 3}
	s.Step(ctx)
	got, _ = s.DB.GetRun(ctx, r.ID)
	if got.FindingsCount != 1 || got.FilesProcessed != 3 {
		t.Fatalf("ingestão parcial: achados=%d processados=%d", got.FindingsCount, got.FilesProcessed)
	}
	// Completa a linha parcial e termina a unidade com resumo.
	fx.appendFindings(t, r.ID, `,"signature":"Php.Webshell.Y","severity":"critical","category":"webshell"}`+"\n")
	st := fx.state(r.ID)
	st.Active, st.Summary = "inactive", &report.Summary{RunID: r.ID, Status: report.StatusCompleted, FilesSeen: 5}
	s.Step(ctx)
	got, _ = s.DB.GetRun(ctx, r.ID)
	if got.Status != "completed" || got.FindingsCount != 2 || got.Summary == nil {
		t.Fatalf("finalização: %+v", got)
	}
	fs, _ := s.DB.ListFindings(ctx, store.FindingFilter{RunID: r.ID})
	if len(fs) != 2 {
		t.Fatalf("achados da execução: %d", len(fs))
	}
	var sawFinding bool
	for len(events) > 0 {
		if ev := <-events; ev.Type == "finding" {
			sawFinding = true
		}
	}
	if !sawFinding {
		t.Fatal("a interface deveria ser avisada dos achados novos")
	}
}

func TestExecutorForaDevolveParaFilaERecusaFalha(t *testing.T) {
	ctx := context.Background()
	s, fx, _ := newService(t)
	r, err := s.Enqueue(ctx, RunRequest{Kind: report.KindFiles, Paths: []string{"/srv"}})
	if err != nil {
		t.Fatal(err)
	}
	fx.down = true
	s.Step(ctx)
	got, _ := s.DB.GetRun(ctx, r.ID)
	if got.Status != store.RunQueued || got.Attempts != 1 {
		t.Fatalf("executor fora deveria devolver para a fila: %+v", got)
	}
	fx.down, fx.refuse = false, "caminho proibido"
	s.Step(ctx)
	got, _ = s.DB.GetRun(ctx, r.ID)
	if got.Status != "failed" || !strings.Contains(got.Error, "caminho proibido") {
		t.Fatalf("recusa do executor deveria falhar a execução: %+v", got)
	}
}

func TestConcorrenciaUmaPorTipoECancelamento(t *testing.T) {
	ctx := context.Background()
	s, fx, _ := newService(t)
	a, _ := s.Enqueue(ctx, RunRequest{Kind: report.KindFiles, Paths: []string{"/a"}})
	b, _ := s.Enqueue(ctx, RunRequest{Kind: report.KindFiles, Paths: []string{"/b"}})
	p, _ := s.Enqueue(ctx, RunRequest{Kind: report.KindProcesses})
	s.Step(ctx)
	if len(fx.started) != 2 {
		t.Fatalf("uma de arquivos e uma de processos: %d iniciadas", len(fx.started))
	}
	if got, _ := s.DB.GetRun(ctx, b.ID); got.Status != store.RunQueued {
		t.Fatalf("segunda de arquivos deveria esperar: %s", got.Status)
	}
	if _, err := s.Cancel(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.DB.GetRun(ctx, b.ID); got.Status != "canceled" {
		t.Fatalf("cancelada na fila: %s", got.Status)
	}
	if _, err := s.SetPaused(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	if !fx.state(a.ID).Frozen {
		t.Fatal("pausa não chegou ao executor")
	}
	if _, err := s.SetLimits(ctx, a.ID, "intensivo"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.DB.GetRun(ctx, a.ID); got.Profile.Name != "intensivo" {
		t.Fatalf("perfil novo não gravado: %+v", got.Profile)
	}
	if _, err := s.Cancel(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	s.Step(ctx)
	if got, _ := s.DB.GetRun(ctx, a.ID); got.Status != "canceled" {
		t.Fatalf("cancelada em andamento sem resumo: %s %s", got.Status, got.Error)
	}
	if _, err := s.Cancel(ctx, a.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("cancelar duas vezes: %v", err)
	}
	_ = p
}

func TestRecuperacaoEInterrompida(t *testing.T) {
	ctx := context.Background()
	s, fx, _ := newService(t)
	r, _ := s.Enqueue(ctx, RunRequest{Kind: report.KindFiles, Paths: []string{"/a"}})
	// Simula core que caiu depois de reservar e antes de entregar ao executor.
	if _, err := s.DB.ReserveNext(ctx, report.KindFiles, time.Minute); err != nil {
		t.Fatal(err)
	}
	s.Recover(ctx)
	if got, _ := s.DB.GetRun(ctx, r.ID); got.Status != store.RunQueued {
		t.Fatalf("reserva perdida deveria voltar à fila: %s", got.Status)
	}
	s.Step(ctx)
	// O executor perde a execução (diretório apagado à mão).
	fx.mu.Lock()
	delete(fx.states, r.ID)
	fx.mu.Unlock()
	s.Step(ctx)
	if got, _ := s.DB.GetRun(ctx, r.ID); got.Status != "interrupted" {
		t.Fatalf("execução sumida do executor: %s", got.Status)
	}
}

func TestAgendamentoGeraExecucao(t *testing.T) {
	ctx := context.Background()
	s, fx, now := newService(t)
	sc := store.Schedule{Name: "noturna", Kind: report.KindFiles, Cron: "*/5 * * * *", Timezone: "UTC",
		Paths: []string{"/home"}, Profile: "leve", Enabled: true}
	if err := s.DB.SaveSchedule(ctx, &sc); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(6 * time.Minute)
	s.Step(ctx)
	if len(fx.started) != 1 || fx.started[0].Profile.Name != "leve" {
		t.Fatalf("agendamento deveria iniciar uma execução: %+v", fx.started)
	}
	runs, _ := s.DB.ListRuns(ctx, store.RunFilter{})
	if len(runs) != 1 || runs[0].Origin != "schedule" || !strings.HasPrefix(runs[0].RequestedBy, "agendamento") {
		t.Fatalf("origem: %+v", runs)
	}
}

func TestValidacaoDoPedido(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newService(t)
	cases := []RunRequest{
		{Kind: report.KindFiles},
		{Kind: report.KindFiles, Paths: []string{"relativo"}},
		{Kind: "outro", Paths: []string{"/a"}},
		{Kind: report.KindFiles, Paths: []string{"/a"}, Profile: "inexistente"},
		{Kind: report.KindFiles, Paths: []string{"/a"}, Priority: 99},
	}
	for i, c := range cases {
		if _, err := s.Enqueue(ctx, c); !errors.Is(err, ErrInvalid) {
			t.Errorf("caso %d deveria ser inválido: %v", i, err)
		}
	}
}

func TestLeituraDeAchadosLimitaConteudo(t *testing.T) {
	dir := t.TempDir()
	long := strings.Repeat("x", 10000)
	f := report.Finding{Engine: "yara-x", Signature: long, Severity: "absurda", SHA256: "XYZ",
		Location: &report.Location{Path: "/a"}, Evidence: map[string]string{"k": long}}
	b, _ := json.Marshal(f)
	sem, _ := json.Marshal(report.Finding{Engine: "yara-x"})
	data := string(b) + "\n" + string(sem) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "f.ndjson"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	list, next, bad, err := readFindings(filepath.Join(dir, "f.ndjson"), 0)
	if err != nil || len(list) != 1 || bad != 1 || next != int64(len(data)) {
		t.Fatalf("leitura: %d achados, %d ruins, next %d (%v)", len(list), bad, next, err)
	}
	g := list[0]
	if len(g.Signature) != maxShort || g.Severity != report.SeverityMedium || g.SHA256 != "" || len(g.Evidence["k"]) != maxText {
		t.Fatalf("saneamento: sig=%d sev=%s sha=%q", len(g.Signature), g.Severity, g.SHA256)
	}
	if _, n, _, _ := readFindings(filepath.Join(dir, "nao-existe"), 7); n != 7 {
		t.Fatal(fmt.Sprint("arquivo ausente mantém o offset: ", n))
	}
}
