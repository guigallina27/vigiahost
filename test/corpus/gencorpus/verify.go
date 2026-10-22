//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/guigallina27/vigiahost/internal/controls"
)

// Conferência do corpus com os motores reais. Os arquivos são abertos aqui (sem seguir links, só regulares) e
// entregues ao yr e ao clamscan como descritores herdados, pelos caminhos /dev/fd/N. Assim nenhum nome controlado
// pelo atacante chega ao motor: nem quebra de linha (que corrompe listas e saídas em texto), nem bytes inválidos
// em UTF-8 (que derrubam o `yr scan -r` 1.21.0), nem troca do arquivo entre a conferência e a abertura.
// É o protótipo do adaptador dos motores da Fase 1A.

// Cada lote abre um processo de cada motor; o clamscan leva dezenas de segundos carregando as assinaturas, então os
// lotes são grandes e o limite de descritores sobe ao máximo (veja raiseNoFile).
const batchSize = 20000

func runVerify(args []string) error {
	flags := flag.NewFlagSet("verificar", flag.ExitOnError)
	dir := flags.String("dir", "", "diretório de um corpus gerado (com manifest.json)")
	rule := flags.String("regra", "", "regra YARA do controle positivo (padrão: a embarcada)")
	// O clamscan analisa uns 80 arquivos por segundo numa thread; no sintético de 1 milhão seriam horas.
	withClam := flags.Bool("clamav", true, "conferir também com o ClamAV")
	_ = flags.Parse(args)
	if *dir == "" {
		return errors.New("informe -dir")
	}
	raw, err := os.ReadFile(filepath.Join(*dir, "manifest.json"))
	if err != nil {
		return err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	rulePath := *rule
	if rulePath == "" {
		f, err := os.CreateTemp("", "controle-*.yar")
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(f.Name()) }()
		if _, err := f.WriteString(controls.YARARule); err != nil {
			return err
		}
		_ = f.Close()
		rulePath = f.Name()
	}

	if err := raiseNoFile(); err != nil {
		return err
	}
	files, err := regularFiles(*dir)
	if err != nil {
		return err
	}
	start := time.Now()
	yaraHits, clamHits, err := scanAll(*dir, files, rulePath, *withClam)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %d arquivos regulares analisados em %.1f s\n", m.Kind, len(files), time.Since(start).Seconds())

	wantYARA, wantClam := map[string]bool{}, map[string]string{}
	for _, e := range m.Entries {
		p := e.Path
		if e.PathHex != "" {
			b, _ := hex.DecodeString(e.PathHex)
			p = string(b)
		}
		for _, r := range e.Expect.YARA {
			if r == controls.YARARuleName {
				wantYARA[p] = true
			}
		}
		if e.Expect.ClamAV != "" {
			wantClam[p] = e.Expect.ClamAV
		}
	}
	problems := compare("YARA-X", wantYARA, yaraHits)
	clamGot := map[string]bool{}
	for p, name := range clamHits {
		clamGot[p] = true
		if want, ok := wantClam[p]; ok && want != name {
			problems = append(problems, fmt.Sprintf("ClamAV: %q reportado como %s, esperado %s", p, name, want))
		}
	}
	wantClamSet := map[string]bool{}
	for p := range wantClam {
		wantClamSet[p] = true
	}
	if *withClam {
		problems = append(problems, compare("ClamAV", wantClamSet, clamGot)...)
	} else {
		fmt.Println("aviso: ClamAV não conferido (-clamav=false)")
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Println("FALHA:", p)
		}
		return fmt.Errorf("%d divergência(s) em %s", len(problems), m.Kind)
	}
	fmt.Printf("ok: %s confere com o manifesto (YARA-X: %d, ClamAV: %d detecções esperadas)\n", m.Kind, len(wantYARA), len(wantClam))
	return nil
}

func compare(engine string, want, got map[string]bool) []string {
	var out []string
	for p := range want {
		if !got[p] {
			out = append(out, fmt.Sprintf("%s não detectou %q", engine, p))
		}
	}
	for p := range got {
		if !want[p] {
			out = append(out, fmt.Sprintf("%s acusou %q, que não deveria", engine, p))
		}
	}
	sort.Strings(out)
	return out
}

// regularFiles lista arquivos regulares sem seguir links; FIFO, sockets e links ficam de fora, como no inventário.
func regularFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && filepath.Base(p) != "manifest.json" {
			rel, _ := filepath.Rel(root, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out, err
}

func scanAll(root string, files []string, rule string, withClam bool) (yara map[string]bool, clam map[string]string, err error) {
	yara, clam = map[string]bool{}, map[string]string{}
	for start := 0; start < len(files); start += batchSize {
		batch := files[start:min(start+batchSize, len(files))]
		opened := make([]*os.File, 0, len(batch))
		names := make([]string, 0, len(batch))
		for _, rel := range batch {
			fd, err := syscall.Open(filepath.Join(root, rel), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
			if err != nil {
				closeAll(opened)
				return nil, nil, fmt.Errorf("abrir %q: %w", rel, err)
			}
			opened = append(opened, os.NewFile(uintptr(fd), "corpus"))
			names = append(names, rel)
		}
		// No processo filho, ExtraFiles[i] vira o descritor 3+i.
		var list bytes.Buffer
		for i := range opened {
			fmt.Fprintf(&list, "/dev/fd/%d\n", 3+i)
		}
		ys, err := runEngine(exec.Command("yr", "scan", "--scan-list", "-o", "ndjson", "--disable-console-logs", rule, "-"), opened, list.Bytes())
		if err != nil {
			closeAll(opened)
			return nil, nil, fmt.Errorf("yr: %w", err)
		}
		for line := range strings.Lines(ys) {
			var r struct {
				Path  string `json:"path"`
				Rules []struct {
					Identifier string `json:"identifier"`
				} `json:"rules"`
			}
			if json.Unmarshal([]byte(line), &r) != nil {
				continue
			}
			if i, ok := fdIndex(r.Path); ok && i < len(names) {
				for _, rr := range r.Rules {
					if rr.Identifier == controls.YARARuleName {
						yara[names[i]] = true
					}
				}
			}
		}
		if !withClam {
			closeAll(opened)
			continue
		}
		// clamscan: limite de 100 MB por arquivo (padrão); arquivos maiores vão para a fila própria na 1A.
		cs, err := runEngine(exec.Command("clamscan", "--no-summary", "--infected", "--stdout", "--file-list=/dev/stdin"), opened, list.Bytes())
		closeAll(opened)
		if err != nil {
			return nil, nil, fmt.Errorf("clamscan: %w", err)
		}
		sc := bufio.NewScanner(strings.NewReader(cs))
		for sc.Scan() {
			line := sc.Text()
			path, rest, ok := strings.Cut(line, ": ")
			if !ok || !strings.HasSuffix(rest, " FOUND") {
				continue
			}
			if i, ok := fdIndex(path); ok && i < len(names) {
				clam[names[i]] = strings.TrimSuffix(rest, " FOUND")
			}
		}
	}
	return yara, clam, nil
}

func runEngine(cmd *exec.Cmd, files []*os.File, stdin []byte) (string, error) {
	cmd.ExtraFiles = files
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	// clamscan sai com 1 quando acha algo; yr sai com 0. Qualquer outro código é falha do motor.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 && cmd.Args[0] == "clamscan" {
		err = nil
	}
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// raiseNoFile fixa o limite flexível de descritores no rígido. Feito explicitamente (e não pelo ajuste automático do
// Go) para que os motores herdem o mesmo limite: o Go devolve aos filhos o limite original quando foi ele que o mudou.
func raiseNoFile() error {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return err
	}
	if lim.Max < batchSize+64 {
		return fmt.Errorf("limite de descritores %d é menor que o lote (%d)", lim.Max, batchSize)
	}
	lim.Cur = lim.Max
	return syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
}

func fdIndex(p string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimPrefix(p, "/dev/fd/"))
	if err != nil || !strings.HasPrefix(p, "/dev/fd/") {
		return 0, false
	}
	return n - 3, true
}

func closeAll(files []*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}
