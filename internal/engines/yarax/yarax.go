// Package yarax é o adaptador do YARA-X pela CLI `yr` (ADR-005). Os arquivos chegam ao `yr` como descritores
// herdados, listados como /dev/fd/N no --scan-list pela entrada padrão; nenhum nome de arquivo da conta é passado
// ao motor (ADR-018). A saída é NDJSON e o caminho de cada linha é só o /dev/fd/N, mapeado de volta pelo índice.
package yarax

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Match é uma regra que casou com um arquivo.
type Match struct {
	Rule      string
	Namespace string
	Tags      []string
	Meta      map[string]string
}

// Scanner executa o `yr` com um conjunto de regras compiladas.
type Scanner struct {
	Bin   string // caminho do yr
	Rules string // arquivo de regras compiladas (yr compile)
	// Timeout por arquivo em segundos (0 = padrão do yr).
	Timeout int
	Threads int
	// MaxFileBytes faz o yr pular arquivos maiores (--skip-larger); 0 = sem limite.
	MaxFileBytes int64
}

// Version devolve a versão do yr (ex.: "1.21.0").
func Version(ctx context.Context, bin string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("yr --version: %w", err)
	}
	f := strings.Fields(string(out))
	if len(f) == 0 {
		return "", errors.New("yr --version sem saída")
	}
	return f[len(f)-1], nil
}

// Source é um arquivo ou diretório de regras com o namespace (a fonte: vigiahost, yara-forge...).
type Source struct {
	Namespace string
	Path      string
}

// Compile compila as fontes num único arquivo. Regras inválidas fazem a compilação falhar inteira: o conjunto só é
// promovido depois de compilar e passar no controle positivo.
func Compile(ctx context.Context, bin string, sources []Source, out string) error {
	args := []string{"compile", "--output", out}
	for _, s := range sources {
		if strings.ContainsAny(s.Namespace, ":/ ") || s.Namespace == "" {
			return fmt.Errorf("namespace inválido: %q", s.Namespace)
		}
		args = append(args, s.Namespace+":"+s.Path)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // binário descoberto em caminho fixo; fontes de regras do próprio produto
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("yr compile: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Result é o resultado de um lote: Matches[i] e Errors[i] correspondem a files[i].
type Result struct {
	Matches [][]Match
	Errors  []string
}

// ScanFiles analisa um lote de arquivos já abertos. O processo filho recebe files[i] como descritor 3+i.
// O limite de descritores (RLIMIT_NOFILE) do processo precisa comportar o lote.
func (s *Scanner) ScanFiles(ctx context.Context, files []*os.File) (Result, error) {
	res := Result{Matches: make([][]Match, len(files)), Errors: make([]string, len(files))}
	if len(files) == 0 {
		return res, nil
	}
	args := []string{"scan", "--compiled-rules", "--scan-list", "--output-format", "ndjson",
		"--print-meta", "--print-namespace", "--print-tags", "--disable-console-logs"}
	if s.Timeout > 0 {
		args = append(args, "--timeout", strconv.Itoa(s.Timeout))
	}
	if s.Threads > 0 {
		args = append(args, "--threads", strconv.Itoa(s.Threads))
	}
	if s.MaxFileBytes > 0 {
		args = append(args, "--skip-larger", strconv.FormatInt(s.MaxFileBytes, 10))
	}
	args = append(args, s.Rules, "-")

	var list bytes.Buffer
	for i := range files {
		fmt.Fprintf(&list, "/dev/fd/%d\n", 3+i)
	}
	cmd := exec.CommandContext(ctx, s.Bin, args...) //nolint:gosec // argumentos fixos; os alvos chegam só como /dev/fd/N
	cmd.ExtraFiles = files
	cmd.Stdin = &list
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()

	for line := range strings.Lines(stdout.String()) {
		var r struct {
			Path  string `json:"path"`
			Rules []struct {
				Identifier string            `json:"identifier"`
				Namespace  string            `json:"namespace"`
				Tags       []string          `json:"tags"`
				Meta       []json.RawMessage `json:"meta"`
			} `json:"rules"`
		}
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		i, ok := fdIndex(r.Path, len(files))
		if !ok {
			continue
		}
		for _, rule := range r.Rules {
			res.Matches[i] = append(res.Matches[i], Match{
				Rule: rule.Identifier, Namespace: rule.Namespace, Tags: rule.Tags, Meta: parseMeta(rule.Meta),
			})
		}
	}
	// Erros por arquivo (tempo esgotado, leitura) vêm no stderr citando o /dev/fd/N.
	sc := bufio.NewScanner(&stderr)
	var general []string
	for sc.Scan() {
		line := sc.Text()
		if idx := strings.Index(line, "/dev/fd/"); idx >= 0 {
			rest := line[idx:]
			end := strings.IndexFunc(rest[len("/dev/fd/"):], func(r rune) bool { return r < '0' || r > '9' })
			p := rest
			if end >= 0 {
				p = rest[:len("/dev/fd/")+end]
			}
			if i, ok := fdIndex(p, len(files)); ok {
				res.Errors[i] = strings.TrimSpace(line)
				continue
			}
		}
		if strings.TrimSpace(line) != "" {
			general = append(general, line)
		}
	}
	if runErr != nil {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		var exitErr *exec.ExitError
		// Código 1 com erros por arquivo identificados é falha parcial; o resto é falha do motor.
		if !errors.As(runErr, &exitErr) || len(general) > 0 || !hasAny(res.Errors) {
			return res, fmt.Errorf("yr scan: %w: %s", runErr, strings.Join(general, "; "))
		}
	}
	return res, nil
}

func hasAny(errs []string) bool {
	for _, e := range errs {
		if e != "" {
			return true
		}
	}
	return false
}

func fdIndex(p string, n int) (int, bool) {
	num, ok := strings.CutPrefix(p, "/dev/fd/")
	if !ok {
		return 0, false
	}
	fd, err := strconv.Atoi(num)
	if err != nil || fd < 3 || fd-3 >= n {
		return 0, false
	}
	return fd - 3, true
}

// parseMeta converte [["chave", valor], ...] em mapa de texto.
func parseMeta(raw []json.RawMessage) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	m := make(map[string]string, len(raw))
	for _, item := range raw {
		var pair []json.RawMessage
		if json.Unmarshal(item, &pair) != nil || len(pair) != 2 {
			continue
		}
		var key string
		if json.Unmarshal(pair[0], &key) != nil {
			continue
		}
		var str string
		if json.Unmarshal(pair[1], &str) == nil {
			m[key] = str
			continue
		}
		m[key] = strings.TrimSpace(string(pair[1]))
	}
	return m
}
