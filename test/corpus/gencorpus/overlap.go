//go:build linux

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/guigallina27/vigiahost/internal/engines/lmd"
)

// Sobreposição do LMD com o ClamAV (ADR-020): o mesmo corpus passa pelo LMD (estágios nativos, pelo adaptador do
// produto, com os arquivos entregues como /proc/<pid>/fd/<n>), pelo clamscan com o banco oficial e pelo clamscan só
// com as assinaturas do LMD (rfxn.hdb, rfxn.ndb, rfxn.yara), que é o que o clamd carrega quando o install.sh do LMD
// as copia para o diretório do ClamAV. O resultado diz o que o LMD acrescenta além do clamd.

type overlapResult struct {
	Corpus  string              `json:"corpus"`
	Files   int                 `json:"files"`
	Batch   int                 `json:"batch"`
	Seconds map[string]float64  `json:"seconds"`
	Hits    map[string][]string `json:"hits"` // motor -> arquivos (relativos) detectados
	Sigs    map[string]map[string]string
}

func runOverlap(args []string) error {
	flags := flag.NewFlagSet("sobreposicao", flag.ExitOnError)
	dir := flags.String("dir", "", "diretório do corpus")
	batch := flags.Int("lote", 5000, "arquivos por sessão do LMD")
	clamDB := flags.String("clamav-db", "/var/lib/clamav", "banco oficial do ClamAV")
	out := flags.String("saida", "", "grava o resultado detalhado em JSON")
	withClam := flags.Bool("clamav", true, "comparar também com o clamscan")
	_ = flags.Parse(args)
	if *dir == "" {
		return errors.New("informe -dir")
	}
	if err := raiseNoFile(); err != nil {
		return err
	}
	files, err := regularFiles(*dir)
	if err != nil {
		return err
	}
	in, err := lmd.Discover(os.DirFS("/"))
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "sobreposicao-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()
	sc := &lmd.Scanner{Install: in, Work: filepath.Join(work, "lmd")}
	if yr, err := exec.LookPath("yr"); err == nil {
		sc.YRDir = filepath.Dir(yr)
	}
	// Só as assinaturas do LMD num diretório próprio do ClamAV (o que o clamd carrega com o LMD instalado).
	rfxnDB := filepath.Join(work, "rfxn-db")
	if err := os.Mkdir(rfxnDB, 0o700); err != nil {
		return err
	}
	for _, n := range []string{"rfxn.hdb", "rfxn.hsb", "rfxn.ndb", "rfxn.yara"} {
		data, err := os.ReadFile(filepath.Join(in.Dir, "sigs", n)) //nolint:gosec // assinaturas do LMD instalado no laboratório
		if err != nil || len(data) == 0 {
			continue
		}
		if err := os.WriteFile(filepath.Join(rfxnDB, n), data, 0o600); err != nil { //nolint:gosec // diretório temporário próprio, nomes fixos
			return err
		}
	}

	res := overlapResult{Corpus: *dir, Files: len(files), Batch: *batch, Seconds: map[string]float64{},
		Hits: map[string][]string{}, Sigs: map[string]map[string]string{}}
	add := func(engine, rel, sig string) {
		if res.Sigs[engine] == nil {
			res.Sigs[engine] = map[string]string{}
		}
		if _, ok := res.Sigs[engine][rel]; !ok {
			res.Hits[engine] = append(res.Hits[engine], rel)
		}
		res.Sigs[engine][rel] = sig
	}
	ctx := context.Background()
	for start := 0; start < len(files); start += *batch {
		names := files[start:min(start+*batch, len(files))]
		opened, err := openAll(*dir, names)
		if err != nil {
			return err
		}
		t0 := time.Now()
		r, err := sc.ScanFiles(ctx, opened)
		res.Seconds["lmd"] += time.Since(t0).Seconds()
		if err != nil {
			closeAll(opened)
			return fmt.Errorf("LMD: %w", err)
		}
		for i, hits := range r.Hits {
			for _, h := range hits {
				add("lmd", names[i], h.Type+" "+h.Signature)
			}
		}
		if *withClam {
			for _, c := range []struct{ name, db string }{{"clamav-oficial", *clamDB}, {"clamav-rfxn", rfxnDB}} {
				t0 := time.Now()
				found, err := clamscanFDs(opened, c.db)
				res.Seconds[c.name] += time.Since(t0).Seconds()
				if err != nil {
					closeAll(opened)
					return fmt.Errorf("clamscan (%s): %w", c.name, err)
				}
				for i, sig := range found {
					add(c.name, names[i], sig)
				}
			}
		}
		closeAll(opened)
	}
	printOverlap(res)
	if *out != "" {
		data, _ := json.MarshalIndent(res, "", "  ")
		return os.WriteFile(*out, data, 0o600)
	}
	return nil
}

func openAll(root string, names []string) ([]*os.File, error) {
	opened := make([]*os.File, 0, len(names))
	for _, rel := range names {
		fd, err := syscall.Open(filepath.Join(root, rel), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
		if err != nil {
			closeAll(opened)
			return nil, fmt.Errorf("abrir %q: %w", rel, err)
		}
		opened = append(opened, os.NewFile(uintptr(fd), "corpus"))
	}
	return opened, nil
}

// clamscanFDs roda o clamscan com o banco indicado, entregando os arquivos como /dev/fd/N.
func clamscanFDs(files []*os.File, db string) (map[int]string, error) {
	var list strings.Builder
	for i := range files {
		fmt.Fprintf(&list, "/dev/fd/%d\n", 3+i)
	}
	cmd := exec.Command("clamscan", "--no-summary", "--infected", "--stdout", "--database="+db, "--file-list=/dev/stdin")
	cmd.ExtraFiles = files
	cmd.Stdin = strings.NewReader(list.String())
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if err != nil && (!errors.As(err, &exitErr) || exitErr.ExitCode() > 1) {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	found := map[int]string{}
	s := bufio.NewScanner(strings.NewReader(stdout.String()))
	for s.Scan() {
		path, rest, ok := strings.Cut(s.Text(), ": ")
		if !ok || !strings.HasSuffix(rest, " FOUND") {
			continue
		}
		if i, ok := fdIndex(path); ok && i >= 0 && i < len(files) {
			found[i] = strings.TrimSuffix(rest, " FOUND")
		}
	}
	return found, nil
}

func printOverlap(r overlapResult) {
	set := func(e string) map[string]bool {
		m := map[string]bool{}
		for _, p := range r.Hits[e] {
			m[p] = true
		}
		return m
	}
	l, c, x := set("lmd"), set("clamav-oficial"), set("clamav-rfxn")
	count := func(a, b map[string]bool, both bool) int {
		n := 0
		for p := range a {
			if b[p] == both {
				n++
			}
		}
		return n
	}
	fmt.Printf("corpus %s: %d arquivos, lotes de %d\n", r.Corpus, r.Files, r.Batch)
	engines := make([]string, 0, len(r.Seconds))
	for e := range r.Seconds {
		engines = append(engines, e)
	}
	sort.Strings(engines)
	for _, e := range engines {
		fmt.Printf("  %-15s %6d arquivos detectados em %8.1f s\n", e, len(r.Hits[e]), r.Seconds[e])
	}
	fmt.Printf("  LMD ∩ ClamAV só rfxn: %d | só LMD: %d | só ClamAV rfxn: %d\n", count(l, x, true), count(l, x, false), count(x, l, false))
	fmt.Printf("  LMD ∩ ClamAV oficial: %d | só LMD: %d | só ClamAV oficial: %d\n", count(l, c, true), count(l, c, false), count(c, l, false))
	union := map[string]bool{}
	for p := range c {
		union[p] = true
	}
	for p := range x {
		union[p] = true
	}
	fmt.Printf("  LMD fora de (oficial ∪ rfxn no ClamAV): %d\n", count(l, union, false))
	for _, e := range []string{"lmd", "clamav-oficial", "clamav-rfxn"} {
		names := r.Hits[e]
		sort.Strings(names)
		for i, p := range names {
			if i == 40 {
				fmt.Printf("    %-15s ... mais %d (veja -saida)\n", e, len(names)-i)
				break
			}
			fmt.Printf("    %-15s %q -> %s\n", e, p, r.Sigs[e][p])
		}
	}
}
