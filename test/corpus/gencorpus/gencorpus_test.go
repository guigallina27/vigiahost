package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSafeJoinRecusaSaidaDoDestino(t *testing.T) {
	dest := t.TempDir()
	for _, bad := range []string{"../fora.php", "a/../../fora.php", "/etc/passwd", "a/\x00b", "", ".", "..\\fora.php"} {
		if _, err := safeJoin(dest, bad); err == nil {
			t.Errorf("%q deveria ser recusado", bad)
		}
	}
	got, err := safeJoin(dest, "wordpress/wp-includes/version.php")
	if err != nil || got != filepath.Join(dest, "wordpress", "wp-includes", "version.php") {
		t.Fatalf("caminho válido: %q, %v", got, err)
	}
}

func TestExtractZipIgnoraLinksERecusaZipSlip(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, entries map[string]string) string {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for n, c := range entries {
			w, err := zw.Create(n)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write([]byte(c))
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	ok := write("ok.zip", map[string]string{"plugin/plugin.php": "<?php", "plugin/readme.txt": "ok"})
	files, _, err := extract(ok, filepath.Join(dir, "ok"))
	if err != nil || files != 2 {
		t.Fatalf("extração válida: %d arquivos, %v", files, err)
	}

	slip := write("slip.zip", map[string]string{"../../fora.php": "<?php"})
	if _, _, err := extract(slip, filepath.Join(dir, "slip")); err == nil {
		t.Fatal("zip slip deveria falhar")
	}
	if _, err := os.Stat(filepath.Join(dir, "fora.php")); err == nil {
		t.Fatal("arquivo gravado fora do destino")
	}
}

func TestControlesPositivosSaoDeterministicos(t *testing.T) {
	a, err := positiveFiles(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := positiveFiles(1 << 20)
	if len(a) != len(b) || len(a) < 10 {
		t.Fatalf("quantidade de controles: %d e %d", len(a), len(b))
	}
	negatives, positives := 0, 0
	for i := range a {
		if !bytes.Equal(a[i].data, b[i].data) || a[i].path != b[i].path {
			t.Fatalf("controle %s não é determinístico", a[i].path)
		}
		if a[i].expect.ClamAV == "" && len(a[i].expect.YARA) == 0 && !a[i].expect.Heuristic {
			negatives++
		} else {
			positives++
		}
	}
	if negatives == 0 || positives == 0 {
		t.Fatalf("precisa de controles positivos e negativos: %d e %d", positives, negatives)
	}
}
