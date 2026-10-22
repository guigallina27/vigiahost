// Package rules embarca as regras YARA escritas pelo projeto e o controle positivo, e prepara o conjunto compilado
// usado pelas execuções. Regras de terceiros não são embarcadas (escopo, seção 7.3): entram por fontes que o
// administrador habilita, baixadas e conferidas no servidor.
package rules

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/guigallina27/vigiahost/internal/controls"
	"github.com/guigallina27/vigiahost/internal/engines/yarax"
)

//go:embed vigiahost/*.yar
var builtin embed.FS

// Namespaces dos conjuntos embarcados; viram a "fonte" de cada achado.
const (
	NamespaceProduct = "vigiahost"
	NamespaceControl = "controle"
)

// Set é um conjunto de regras pronto para compilar: arquivos já gravados em disco por namespace.
type Set struct {
	Sources []yarax.Source
	// Version identifica o conteúdo exato das regras (hash dos arquivos), registrada em cada execução.
	Version string
}

// Materialize grava as regras embarcadas em dir e devolve o conjunto. Fontes extras (habilitadas pelo
// administrador) entram em extra, já baixadas e conferidas.
func Materialize(dir string, extra ...yarax.Source) (Set, error) {
	if err := os.MkdirAll(filepath.Join(dir, NamespaceProduct), 0o700); err != nil {
		return Set{}, err
	}
	h := sha256.New()
	names, err := fs.Glob(builtin, "vigiahost/*.yar")
	if err != nil {
		return Set{}, err
	}
	sort.Strings(names)
	for _, n := range names {
		data, err := builtin.ReadFile(n)
		if err != nil {
			return Set{}, err
		}
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", n, len(data))
		h.Write(data)
		if err := os.WriteFile(filepath.Join(dir, n), data, 0o600); err != nil {
			return Set{}, err
		}
	}
	control := filepath.Join(dir, "controle-positivo.yar")
	_, _ = fmt.Fprintf(h, "controle\x00%d\x00", len(controls.YARARule))
	h.Write([]byte(controls.YARARule))
	if err := os.WriteFile(control, []byte(controls.YARARule), 0o600); err != nil {
		return Set{}, err
	}
	set := Set{Sources: []yarax.Source{
		{Namespace: NamespaceControl, Path: control},
		{Namespace: NamespaceProduct, Path: filepath.Join(dir, NamespaceProduct)},
	}}
	for _, e := range extra {
		if err := hashTree(h, e); err != nil {
			return Set{}, err
		}
		set.Sources = append(set.Sources, e)
	}
	set.Version = hex.EncodeToString(h.Sum(nil))[:16]
	return set, nil
}

func hashTree(h interface{ Write([]byte) (int, error) }, s yarax.Source) error {
	return filepath.WalkDir(s.Path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(p) //nolint:gosec // fonte de regras habilitada pelo administrador
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(h, "%s:%s\x00%d\x00", s.Namespace, p, len(data))
		_, _ = h.Write(data)
		return nil
	})
}

// Compiled devolve o arquivo compilado do conjunto, compilando só se a versão mudou. O arquivo fica em
// dir/compiled-<versão do yr>-<versão das regras>.yarc.
func Compiled(ctx context.Context, yr, yrVersion, dir string, set Set) (string, error) {
	if set.Version == "" {
		return "", errors.New("conjunto de regras sem versão")
	}
	out := filepath.Join(dir, "compiled-"+yrVersion+"-"+set.Version+".yarc")
	if info, err := os.Stat(out); err == nil && info.Size() > 0 {
		return out, nil
	}
	tmp := out + ".tmp"
	if err := yarax.Compile(ctx, yr, set.Sources, tmp); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, out); err != nil {
		return "", err
	}
	// Conjuntos antigos ficam só até o próximo: o anterior serve de retorno.
	old, _ := filepath.Glob(filepath.Join(dir, "compiled-*.yarc"))
	sort.Slice(old, func(i, j int) bool {
		a, _ := os.Stat(old[i])
		b, _ := os.Stat(old[j])
		return a != nil && b != nil && a.ModTime().After(b.ModTime())
	})
	for _, o := range old[min(len(old), 2):] {
		_ = os.Remove(o)
	}
	return out, nil
}
