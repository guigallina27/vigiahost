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
	if err := w.walkRoot(root); err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	return files, skips
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
