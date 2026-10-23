package updates

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/pkgverify"
)

// stderrRunner devolve saída e erro padrão por trecho do comando, na ordem das chamadas repetidas.
type stderrRunner struct {
	calls []string
	resp  func(cmd string, n int) (out, stderr string, code int)
}

func (s *stderrRunner) Run(_ context.Context, w io.Writer, name string, args ...string) (string, int, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	s.calls = append(s.calls, cmd)
	out, stderr, code := s.resp(cmd, len(s.calls))
	_, _ = io.WriteString(w, out)
	return stderr, code, nil
}

// Contêiner ou servidor que nunca baixou a lista: não é falha da execução, é o achado "lista de pacotes ausente".
func TestCollectRPMWithoutCache(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "usr", "bin", "dnf"), nil, 0o644)
	r := &stderrRunner{resp: func(string, int) (string, string, int) { return "", "", 0 }}
	c := &Collector{Manager: pkgverify.RPM, Runner: r, Root: root, Proc: filepath.Join(root, "proc")}
	rep := c.Collect(context.Background())
	if rep.Error != "" || rep.Security == nil || rep.Other == nil {
		t.Fatalf("%+v", rep)
	}
	for _, call := range r.calls {
		if strings.Contains(call, "updateinfo") {
			t.Fatalf("dnf consultado sem cache: %v", r.calls)
		}
	}
	found := false
	for _, f := range Findings(rep, time.Now()) {
		found = found || f.Signature == "atualizacao.lista_de_pacotes_ausente"
	}
	if !found {
		t.Fatal("faltou o achado de lista ausente")
	}
}

// Um repositório sem lista no cache: confere os demais (skip_if_unavailable) e avisa.
func TestCollectRPMRepoWithoutCache(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"usr/bin/dnf", "var/cache/dnf/baseos-1/repodata/repomd.xml"} {
		full := filepath.Join(root, filepath.FromSlash(p))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, nil, 0o644)
	}
	adv := string(fixture(t, "alma9/dnf-updateinfo-security.txt"))
	r := &stderrRunner{resp: func(cmd string, _ int) (string, string, int) {
		if strings.Contains(cmd, "updateinfo") && !strings.Contains(cmd, "skip_if_unavailable") {
			return "", "Error: Cache-only enabled but no cache for 'appstream'\n", 1
		}
		if strings.Contains(cmd, "updateinfo list --security") && !strings.Contains(cmd, "--with-cve") {
			return adv, "", 0
		}
		return "", "", 0
	}}
	c := &Collector{Manager: pkgverify.RPM, Runner: r, Root: root, Proc: filepath.Join(root, "proc")}
	rep := c.Collect(context.Background())
	if rep.Error != "" || len(rep.Warnings) == 0 || !strings.Contains(rep.Warnings[0], "appstream") {
		t.Fatalf("erro %q avisos %v", rep.Error, rep.Warnings)
	}
}
