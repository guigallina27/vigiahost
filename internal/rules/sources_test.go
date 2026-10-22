package rules

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/guigallina27/vigiahost/internal/engines/yarax"
)

const regraBoa = "rule local_boa { strings: $a = \"VIGIAHOST-FONTE-LOCAL\" condition: $a }\n"

func writeSource(t *testing.T, root, name string, files map[string]string) {
	t.Helper()
	for rel, data := range files {
		p := filepath.Join(root, name, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil { //nolint:gosec // teste
			t.Fatal(err)
		}
	}
}

func trustAll(t *testing.T) {
	old := trusted
	trusted = func(fs.FileInfo) bool { return true }
	t.Cleanup(func() { trusted = old })
}

func TestBuiltin(t *testing.T) {
	b := Builtin()
	if len(b) != 2 || b[0].Name != NamespaceControl || !b[0].Mandatory || b[1].Name != NamespaceProduct {
		t.Fatalf("embarcadas = %+v", b)
	}
	if b[0].Rules != 1 || b[1].Rules != 15 || b[1].Files != 2 || len(b[1].Hash) != 64 || b[1].License != "GPL-3.0-only" {
		t.Errorf("embarcadas = %+v", b)
	}
}

func TestInspectLocal(t *testing.T) {
	trustAll(t)
	root := t.TempDir()
	writeSource(t, root, "boa", map[string]string{
		"a.yar":       regraBoa,
		"sub/b.yara":  "private rule x { condition: false }\nrule y { condition: x }\n",
		"README.md":   "ignorado",
		"source.json": `{"description":"Regras da equipe","license":"MIT","author":"Equipe","url":"https://exemplo.invalid/regras","version":"3"}`,
	})
	writeSource(t, root, "Maiuscula", map[string]string{"a.yar": regraBoa})
	writeSource(t, root, "vigiahost", map[string]string{"a.yar": regraBoa})
	writeSource(t, root, "inclui", map[string]string{"a.yar": "include \"/etc/shadow\"\n" + regraBoa})
	writeSource(t, root, "vazia", map[string]string{"leia.txt": "nada"})
	writeSource(t, root, "meta", map[string]string{"a.yar": regraBoa, "source.json": `{"url":"http://inseguro.invalid"}`})
	writeSource(t, root, "extra", map[string]string{"a.yar": regraBoa, "source.json": `{"campo":"desconhecido"}`})
	if err := os.WriteFile(filepath.Join(root, "LEIA-ME"), []byte("x"), 0o644); err != nil { //nolint:gosec // teste
		t.Fatal(err)
	}

	list := Inspect(root)
	got := map[string]SourceInfo{}
	for _, s := range list {
		if s.Origin == OriginLocal {
			got[s.Name] = s
		}
	}
	// Duas embarcadas, sete locais (inclusive a que tenta usar o nome reservado); o arquivo solto não é fonte.
	if len(list) != 9 || len(got) != 7 {
		t.Fatalf("fontes = %+v", list)
	}
	boa := got["boa"]
	if boa.Problem != "" || boa.Files != 2 || boa.Rules != 3 || boa.License != "MIT" || boa.Version != "3" ||
		boa.Origin != OriginLocal || len(boa.Hash) != 64 || boa.UpdatedAt.IsZero() {
		t.Errorf("fonte boa = %+v", boa)
	}
	for name, want := range map[string]string{"Maiuscula": "nome inválido", "vigiahost": "reservado", "inclui": "include",
		"vazia": "nenhum arquivo", "meta": "https://", "extra": "source.json inválido"} {
		if p := got[name].Problem; !strings.Contains(p, want) {
			t.Errorf("%s: problema %q, esperado %q", name, p, want)
		}
	}
	// O hash muda com o conteúdo.
	writeSource(t, root, "boa", map[string]string{"a.yar": regraBoa + "rule z { condition: false }\n"})
	if again, _ := inspectLocal(root, "boa", ""); again.Hash == boa.Hash || again.Rules != 4 {
		t.Errorf("alteração não percebida: %+v", again)
	}
}

func TestInspectLocalPermissions(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "aberta", map[string]string{"a.yar": regraBoa})
	old := trusted
	defer func() { trusted = old }()
	trusted = func(fi fs.FileInfo) bool { return fi.Name() != "a.yar" }
	if info, _ := inspectLocal(root, "aberta", ""); !strings.Contains(info.Problem, "root") {
		t.Errorf("arquivo gravável por outros aceito: %+v", info)
	}
	trusted = func(fi fs.FileInfo) bool { return fi.Name() != "aberta" }
	if info, _ := inspectLocal(root, "aberta", ""); !strings.Contains(info.Problem, "root") {
		t.Errorf("diretório gravável por outros aceito: %+v", info)
	}
}

func TestValidDisabled(t *testing.T) {
	if err := ValidDisabled([]string{"vigiahost", "boa"}); err != nil {
		t.Error(err)
	}
	for _, bad := range [][]string{{"controle"}, {"../x"}, {"a", "a"}, {"Maiuscula"}} {
		if ValidDisabled(bad) == nil {
			t.Errorf("%v aceito", bad)
		}
	}
}

func TestPrepare(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("YARA-X só no laboratório Linux")
	}
	yr, err := exec.LookPath("yr")
	if err != nil {
		t.Skip("yr não instalado")
	}
	trustAll(t)
	ctx := context.Background()
	v, err := yarax.Version(ctx, yr)
	if err != nil {
		t.Fatal(err)
	}
	user := t.TempDir()
	writeSource(t, user, "boa", map[string]string{"a.yar": regraBoa})
	writeSource(t, user, "quebrada", map[string]string{"a.yar": "rule quebrada { condition: \n"})
	writeSource(t, user, "inclui", map[string]string{"a.yar": "include \"x.yar\"\n"})
	writeSource(t, user, "desligada", map[string]string{"a.yar": regraBoa})
	dir := t.TempDir()

	_, compiled, st, err := Prepare(ctx, yr, v, dir, PrepareOptions{UserDir: user, Disabled: []string{"desligada"}, Trigger: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, s := range st.Sources {
		states[s.Name] = s.State
	}
	want := map[string]string{"controle": StateOK, "vigiahost": StateOK, "boa": StateOK, "quebrada": StateError,
		"inclui": StateRefused, "desligada": StateDisabled}
	for n, s := range want {
		if states[n] != s {
			t.Errorf("%s: estado %q, esperado %q (%+v)", n, states[n], s, st.Sources)
		}
	}
	if !st.OK || st.SetVersion == "" {
		t.Fatalf("compilação = %+v", st)
	}
	saved, err := ReadStatus(dir)
	if err != nil || saved.SetVersion != st.SetVersion || saved.Trigger != "manual" {
		t.Fatalf("status gravado = %+v, %v", saved, err)
	}
	// A fonte local entrou no conjunto com o próprio namespace.
	f, err := os.CreateTemp(t.TempDir(), "amostra")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("VIGIAHOST-FONTE-LOCAL")
	_, _ = f.Seek(0, 0)
	res, err := (&yarax.Scanner{Bin: yr, Rules: compiled}).ScanFiles(ctx, []*os.File{f})
	_ = f.Close()
	if err != nil || len(res.Matches[0]) != 1 || res.Matches[0][0].Namespace != "boa" {
		t.Fatalf("regra local não detectou: %+v %v", res.Matches, err)
	}

	// Sem as regras do projeto o conjunto muda de versão e mantém o controle positivo.
	_, _, st2, err := Prepare(ctx, yr, v, dir, PrepareOptions{UserDir: user, Disabled: []string{"vigiahost", "desligada"}, Trigger: "scan"})
	if err != nil || st2.SetVersion == st.SetVersion {
		t.Fatalf("conjunto sem vigiahost = %+v, %v", st2, err)
	}
}
