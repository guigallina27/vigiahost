package setup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/scan"
)

// fakeSystemd guarda o estado das unidades e as chamadas feitas.
type fakeSystemd struct {
	enabled, active map[string]bool
	calls           []string
}

func (f *fakeSystemd) run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	switch args[0] {
	case "is-enabled":
		if f.enabled[args[1]] {
			return "enabled", nil
		}
		return "disabled", nil
	case "is-active":
		if f.active[args[1]] {
			return "active", nil
		}
		return "inactive", nil
	case "enable":
		f.enabled[args[2]], f.active[args[2]] = true, true
	case "disable":
		f.enabled[args[2]], f.active[args[2]] = false, false
	}
	return "", nil
}

func newTestSystem(t *testing.T) (*System, *fakeSystemd) {
	t.Helper()
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "etc", "os-release"), []byte("ID=almalinux\nID_LIKE=\"rhel centos fedora\"\nNAME=\"AlmaLinux\"\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(root, "run", "systemd", "system"), 0o755)
	f := &fakeSystemd{enabled: map[string]bool{}, active: map[string]bool{}}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	return &System{Root: root, Systemctl: f.run, Now: func() time.Time { return now },
		Engines: func(context.Context) scan.EngineInfo {
			return scan.EngineInfo{YR: "/usr/local/bin/yr", YRVersion: "1.21.0"}
		}}, f
}

func TestPlanoAplicaReexecutaEDesfaz(t *testing.T) {
	s, f := newTestSystem(t)
	ctx := context.Background()
	opts := Options{Listen: "127.0.0.1:0"} // porta 0: sempre livre no teste
	env := s.Detect(ctx, opts.Listen)
	env.Systemd = true
	p := s.MakePlan(env, opts, nil)
	if len(p.Blockers) != 0 {
		t.Fatalf("impedimentos inesperados: %v", p.Blockers)
	}
	if !p.Pending() || p.Actions[0].ID != "core-config" {
		t.Fatalf("plano: %+v", p.Actions)
	}
	var out bytes.Buffer
	m, err := s.Apply(ctx, p, nil, &out)
	if err != nil {
		t.Fatal(err)
	}
	drop, err := os.ReadFile(s.path(CoreDropIn))
	if err != nil || !strings.Contains(string(drop), "serve -listen 127.0.0.1:0") {
		t.Fatalf("drop-in: %q %v", drop, err)
	}
	if !f.enabled["vigiahost-core.service"] || !f.active["vigiahost-executor.service"] || len(m.Changes) != 3 {
		t.Fatalf("serviços ou manifesto: %+v %+v", f.enabled, m.Changes)
	}

	// Reexecução: nada a fazer, nenhuma alteração nova no manifesto.
	prev, _ := s.LoadManifest()
	env = s.Detect(ctx, "")
	env.Systemd = true
	p2 := s.MakePlan(env, opts, prev)
	if p2.Pending() {
		t.Fatalf("reexecução deveria estar em dia: %+v", p2.Actions)
	}

	// Desinstalação sem purge: desfaz o drop-in e os serviços, preserva os dados.
	_ = os.MkdirAll(s.path("/var/lib/vigiahost"), 0o700)
	if err := s.Uninstall(ctx, false, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.path(CoreDropIn)); !os.IsNotExist(err) {
		t.Fatal("o drop-in criado pelo setup devia ter saído")
	}
	if f.enabled["vigiahost-core.service"] || f.active["vigiahost-executor.service"] {
		t.Fatal("serviços deviam estar parados e desabilitados")
	}
	if _, err := os.Stat(s.path("/var/lib/vigiahost")); err != nil {
		t.Fatal("sem --purge os dados ficam")
	}
	if err := s.Uninstall(ctx, true, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.path("/var/lib/vigiahost")); !os.IsNotExist(err) {
		t.Fatal("com --purge os dados saem")
	}
}

func TestArquivoExistenteGanhaBackupERestauracao(t *testing.T) {
	s, _ := newTestSystem(t)
	ctx := context.Background()
	if err := s.writeFile(CoreDropIn, []byte("[Service]\n# do administrador\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := s.Detect(ctx, "")
	env.Systemd = true
	p := s.MakePlan(env, Options{Listen: "0.0.0.0:0", TrustProxy: true}, nil)
	m, err := s.Apply(ctx, p, nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	c := m.find("file", CoreDropIn)
	if c == nil || c.Created || !strings.HasPrefix(c.Backup, BackupRoot+"/setup-20261022-120000") {
		t.Fatalf("backup não registrado: %+v", c)
	}
	if err := s.Uninstall(ctx, false, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(s.path(CoreDropIn))
	if string(b) != "[Service]\n# do administrador\n" {
		t.Fatalf("arquivo do administrador não restaurado: %q", b)
	}
}

func TestImpedimentosEAvisos(t *testing.T) {
	s, _ := newTestSystem(t)
	env := s.Detect(context.Background(), "")
	env.Systemd = false
	env.Services["vigiahost-core.service"] = ServiceState{Enabled: "not-found"}
	env.Engines = scan.EngineInfo{}
	env.Family = "debian"
	p := s.MakePlan(env, Options{Listen: "0.0.0.0:8743", TLSCert: "/nao/existe.pem"}, nil)
	joined := strings.Join(p.Blockers, "\n")
	for _, want := range []string{"systemd", "vigiahost-core.service não encontrada", "-tls-cert e -tls-key", "arquivo não encontrado"} {
		if !strings.Contains(joined, want) {
			t.Errorf("faltou impedimento %q em:\n%s", want, joined)
		}
	}
	if _, err := s.Apply(context.Background(), p, nil, &bytes.Buffer{}); err == nil {
		t.Fatal("apply com impedimentos deveria recusar")
	}
	rec := strings.Join(p.Recommendations, "\n")
	if !strings.Contains(rec, "apt install clamav clamav-daemon") || !strings.Contains(rec, "yara-x") {
		t.Errorf("recomendações: %s", rec)
	}
	var out bytes.Buffer
	p.Render(&out)
	if !strings.Contains(out.String(), "Impedimentos") {
		t.Errorf("render sem impedimentos:\n%s", out.String())
	}
}
