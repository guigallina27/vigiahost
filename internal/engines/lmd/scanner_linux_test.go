package lmd

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/guigallina27/vigiahost/internal/controls"
)

// fakeMaldet imita o maldet 2.0 o bastante para exercitar o adaptador sem o LMD instalado: lê a lista, acusa os
// arquivos com o EICAR, grava a sessão TSV e responde ao --json-report conforme o modo gravado ao lado do script.
const fakeMaldet = `#!/bin/bash
dir=$(dirname "$0")
modo=$(cat "$dir/modo")
id=261022-2001.201
base="$LMD_BASEDIR"
case "$1" in
-co)
	printf '%s\n' "$2" > "$dir/opcoes"
	printf '%s\n' "$LMD_BASEDIR" > "$dir/basedir"
	hits=""
	while IFS= read -r p; do
		if grep -q EICAR "$p"; then
			hits+="{HEX}test.test.eicar"$'\t'"$p"$'\t-\tHEX\tHEX Pattern\tabc\t64\troot\troot\t500\t1\n'
		fi
	done < "$4"
	printf '#LMD:v1\tscan\t%s\th\t%s\t%s\ta\tb\t1\t0\t2\t1\t0\t2.0.1\t2026052490478\tsha256\tnative\n' "$id" "$4" "$4" > "$base/sess/session.tsv.$id"
	printf "$hits" >> "$base/sess/session.tsv.$id"
	echo "{sigup} ruído" >&2
	echo "maldet(1): {scan} scan report saved, to view run: maldet --report $id"
	[ "$modo" = erro ] && { echo "maldet(1): falha simulada" >&2; exit 1; }
	[ -n "$hits" ] && exit 2
	exit 0
	;;
--json-report)
	[ "$modo" = tsv ] && exit 1
	q=false; [ "$modo" = quarentena ] && q=true
	printf '{"schema_version":"1.2","scanner":{"version":"2.0.1"},"reports":[{"scan_id":"%s","total_files":2,"total_hits":1,"quarantine_enabled":%s,"hits":[' "$2" "$q"
	sep=""
	while IFS=$'\t' read -r sig file rest; do
		case "$sig" in \#*) continue ;; esac
		printf '%s{"signature":"%s","file":"%s","hit_type":"HEX","hash":"abc"}' "$sep" "$sig" "$file"
		sep=","
	done < "$LMD_BASEDIR/sess/session.tsv.$2"
	printf ']}]}\n'
	;;
esac
`

func fakeLMD(t *testing.T, modo string) *Scanner {
	t.Helper()
	dir := t.TempDir()
	inst := filepath.Join(dir, "maldetect")
	for _, d := range []string{"internals", "sigs", "sess", "tmp"} {
		if err := os.MkdirAll(filepath.Join(inst, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(inst, "maldet"), []byte(fakeMaldet), 0o755); err != nil { //nolint:gosec // script de teste
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inst, "modo"), []byte(modo), 0o644); err != nil { //nolint:gosec // teste
		t.Fatal(err)
	}
	return &Scanner{Install: Install{Dir: inst, Version: "2.0.1"}, Work: filepath.Join(dir, "work"), Workers: 2}
}

func memFiles(t *testing.T, contents ...[]byte) []*os.File {
	t.Helper()
	var out []*os.File
	for _, c := range contents {
		fd, err := unix.MemfdCreate("teste", unix.MFD_CLOEXEC)
		if err != nil {
			t.Fatal(err)
		}
		f := os.NewFile(uintptr(fd), "teste")
		if _, err := f.Write(c); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		out = append(out, f)
	}
	return out
}

func TestScanFilesFake(t *testing.T) {
	for _, modo := range []string{"json", "tsv"} {
		t.Run(modo, func(t *testing.T) {
			s := fakeLMD(t, modo)
			files := memFiles(t, []byte("texto comum\n"), controls.EICAR())
			res, err := s.ScanFiles(context.Background(), files)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Hits[0]) != 0 || len(res.Hits[1]) != 1 || res.Hits[1][0].Signature != "{HEX}test.test.eicar" {
				t.Fatalf("detecções = %+v", res.Hits)
			}
			if res.FromTSV != (modo == "tsv") || res.ScanID != "261022-2001.201" || res.Unmapped != 0 {
				t.Errorf("resultado = %+v", res)
			}
			opts, _ := os.ReadFile(filepath.Join(s.Install.Dir, "opcoes"))
			if !strings.Contains(string(opts), "quarantine_hits=0") || !strings.Contains(string(opts), "scan_clamscan=0") ||
				!strings.Contains(string(opts), "scan_yara=0") {
				t.Errorf("opções forçadas = %s", opts)
			}
			basedir, _ := os.ReadFile(filepath.Join(s.Install.Dir, "basedir"))
			if strings.TrimSpace(string(basedir)) != filepath.Join(s.Work, "base") {
				t.Errorf("LMD_BASEDIR = %s", basedir)
			}
			// A árvore-sombra tem sessão própria e a quarentena é um arquivo sem permissão.
			if info, err := os.Lstat(filepath.Join(s.Work, "base", "quarantine")); err != nil || !info.Mode().IsRegular() {
				t.Errorf("quarentena da árvore-sombra = %v, %v", info, err)
			}
			if info, err := os.Lstat(filepath.Join(s.Work, "base", "internals")); err != nil || info.Mode().Type() != fs.ModeSymlink {
				t.Errorf("internals deveria ser link para a instalação: %v %v", info, err)
			}
			// Segundo lote reaproveita a árvore e começa com a sessão vazia.
			if _, err := s.ScanFiles(context.Background(), files[:1]); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestScanFilesFakeRefuses(t *testing.T) {
	s := fakeLMD(t, "quarentena")
	if _, err := s.ScanFiles(context.Background(), memFiles(t, controls.EICAR())); err == nil || !strings.Contains(err.Error(), "quarentena") {
		t.Errorf("quarentena ligada deveria descartar o lote: %v", err)
	}
	s = fakeLMD(t, "erro")
	_, err := s.ScanFiles(context.Background(), memFiles(t, []byte("x")))
	if err == nil || !strings.Contains(err.Error(), "código 1") || !strings.Contains(err.Error(), "falha simulada") {
		t.Errorf("erro do maldet = %v", err)
	}
}

// TestScanFilesReal roda o LMD instalado (laboratório, como root) com os controles do autoteste.
func TestScanFilesReal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("precisa de root")
	}
	in, err := Discover(os.DirFS("/"))
	if err != nil {
		t.Skipf("LMD indisponível: %v", err)
	}
	s := &Scanner{Install: in, Work: t.TempDir()}
	res, err := s.ScanFiles(context.Background(), memFiles(t, controls.EICAR(), controls.NegativeFile()))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits[0]) == 0 || !strings.Contains(strings.ToLower(res.Hits[0][0].Signature), "eicar") || len(res.Hits[1]) != 0 {
		t.Fatalf("autoteste do LMD real: %+v", res.Hits)
	}
	t.Logf("LMD %s, assinaturas %s: %s", in.Version, in.SigVersion, res)
}
