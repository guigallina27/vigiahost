package scan

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/guigallina27/vigiahost/internal/report"
)

func collect(t *testing.T, root string, exclude ...string) (files []string, skips map[report.SkipReason]int) {
	t.Helper()
	return collectOwned(t, root, nil, exclude...)
}

func collectOwned(t *testing.T, root string, owners []uint32, exclude ...string) (files []string, skips map[report.SkipReason]int) {
	t.Helper()
	skips = map[report.SkipReason]int{}
	w := &walker{
		exclude: exclude, maxDepth: 64, visited: map[[2]uint64]bool{},
		seen: func() {},
		skip: func(r report.SkipReason, _ string) { skips[r]++ },
		warn: func(string) {},
		stop: func() bool { return false },
		emit: func(fl *file) {
			files = append(files, fl.raw)
			_ = fl.f.Close()
		},
	}
	if err := w.walkRootOwned(root, owners); err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	return files, skips
}

func TestWalkComFiltroDeDonoSoPegaArquivosDaConta(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sessao"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "sessao", "x.php"), []byte("<?php"), 0o644)
	_ = os.Symlink("/etc/passwd", filepath.Join(root, "link"))
	me := uint32(os.Geteuid()) //nolint:gosec // UID não negativo
	files, _ := collectOwned(t, root, []uint32{me})
	if len(files) != 1 {
		t.Fatalf("arquivos do próprio dono: %q", files)
	}
	// Outra conta: nada entra, e o que é de outro dono nem conta como ignorado (fica fora do escopo).
	files, skips := collectOwned(t, root, []uint32{me + 1})
	if len(files) != 0 || len(skips) != 0 {
		t.Fatalf("arquivos de outro dono entraram: %q %v", files, skips)
	}
}

func TestWalkNaoSegueLinksNemAbreEspeciais(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(outside, "segredo.txt"), []byte("fora do escopo"), 0o600))
	must(os.MkdirAll(filepath.Join(root, "a", "b"), 0o755))
	must(os.WriteFile(filepath.Join(root, "a", "b", "x.php"), []byte("<?php"), 0o644))
	must(os.WriteFile(filepath.Join(root, "quebra\nlinha.php"), []byte("<?php"), 0o644))
	must(os.WriteFile(filepath.Join(root, "bytes-\xff.php"), []byte("<?php"), 0o644))
	must(os.Symlink(outside, filepath.Join(root, "link-dir")))
	must(os.Symlink(filepath.Join(outside, "segredo.txt"), filepath.Join(root, "link-arquivo")))
	must(os.Symlink(root, filepath.Join(root, "a", "laco")))
	must(syscall.Mkfifo(filepath.Join(root, "fila"), 0o600))
	must(os.Link(filepath.Join(root, "a", "b", "x.php"), filepath.Join(root, "hardlink.php")))
	must(os.MkdirAll(filepath.Join(root, "cache"), 0o755))
	must(os.WriteFile(filepath.Join(root, "cache", "ignorar.php"), []byte("<?php"), 0o644))

	files, skips := collect(t, root, filepath.Join(root, "cache"))
	want := []string{
		filepath.Join(root, "a", "b", "x.php"),
		filepath.Join(root, "bytes-\xff.php"),
		filepath.Join(root, "hardlink.php"),
		filepath.Join(root, "quebra\nlinha.php"),
	}
	slices.Sort(want)
	if !slices.Equal(files, want) {
		t.Fatalf("arquivos:\n%q\nesperado:\n%q", files, want)
	}
	if skips[report.SkipNotRegular] != 4 { // 3 links + FIFO
		t.Errorf("não regulares: %d (%v)", skips[report.SkipNotRegular], skips)
	}
	if skips[report.SkipExcluded] != 1 {
		t.Errorf("excluídos: %v", skips)
	}
}

func TestWalkSemPermissaoContaComoIgnorado(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lê tudo")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "fechado.php"), []byte("<?php"), 0o000); err != nil {
		t.Fatal(err)
	}
	files, skips := collect(t, root)
	if len(files) != 0 || skips[report.SkipPermission] != 1 {
		t.Fatalf("%v %v", files, skips)
	}
}

func TestWalkArquivoApagadoDuranteAVarreduraNaoContaComoIgnorado(t *testing.T) {
	root := t.TempDir()
	skips := map[report.SkipReason]int{}
	seen := 0
	w := &walker{maxDepth: 64, visited: map[[2]uint64]bool{}, seen: func() { seen++ },
		skip: func(r report.SkipReason, _ string) { skips[r]++ }, warn: func(string) {}, stop: func() bool { return false },
		emit: func(fl *file) { _ = fl.f.Close() }}
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(fd) }()
	// Entrada listada que sumiu antes do fstatat (outro processo apagou o arquivo temporário).
	w.entry(fd, root, "apagado.tmp", 0, 0)
	if seen != 0 || len(skips) != 0 {
		t.Fatalf("arquivo apagado contou como visto (%d) ou ignorado (%v)", seen, skips)
	}
}
