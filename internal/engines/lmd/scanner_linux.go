package lmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// ScanFiles analisa um lote de arquivos já abertos. O maldet recebe a lista /proc/<pid>/fd/<n> deste processo (o
// processo da varredura mantém os descritores abertos até o fim do lote) e o resultado volta pelo relatório JSON
// da sessão, com o TSV da sessão como reserva. Não é seguro para uso concorrente (a sessão é uma só).
func (s *Scanner) ScanFiles(ctx context.Context, files []*os.File) (Result, error) {
	res := Result{Hits: make([][]Hit, len(files))}
	if len(files) == 0 {
		return res, nil
	}
	base, err := s.base()
	if err != nil {
		return res, fmt.Errorf("árvore do LMD: %w", err)
	}
	if err := resetSession(base); err != nil {
		return res, err
	}
	pid := os.Getpid()
	fds := make(map[int]int, len(files))
	var list bytes.Buffer
	for i, f := range files {
		fd := int(f.Fd())
		fds[fd] = i
		fmt.Fprintf(&list, "/proc/%d/fd/%d\n", pid, fd)
	}
	listPath := filepath.Join(s.Work, "lista")
	if err := os.WriteFile(listPath, list.Bytes(), 0o600); err != nil {
		return res, err
	}
	defer func() { _ = os.Remove(listPath) }()

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = time.Hour
	}
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out := &tail{max: 64 << 10}
	errOut := &tail{max: 64 << 10}
	code, err := s.run(sctx, base, out, errOut, "-co", coOptions(s.YRDir != "", s.Workers), "-f", listPath)
	if err != nil {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if sctx.Err() != nil {
			return res, fmt.Errorf("maldet excedeu o tempo do lote (%s)", timeout)
		}
		return res, fmt.Errorf("maldet: %w", err)
	}
	// 0: nada encontrado; 2: detecções; 1: erro (ou nenhum arquivo legível).
	if code != 0 && code != 2 {
		return res, fmt.Errorf("maldet terminou com código %d: %s", code, cleanStderr(errOut.buf))
	}
	id := ScanIDFromOutput(out.buf)
	if id == "" {
		if b, err := os.ReadFile(filepath.Join(base, "sess", "session.last")); err == nil { //nolint:gosec // árvore própria
			id = string(bytes.TrimSpace(b))
		}
	}
	if !ScanIDPattern.MatchString(id) {
		return res, fmt.Errorf("maldet não informou a sessão da varredura: %s", cleanStderr(errOut.buf))
	}
	res.ScanID = id
	rep, err := s.report(ctx, base, id)
	if err != nil {
		tsv, terr := os.ReadFile(filepath.Join(base, "sess", "session.tsv."+id)) //nolint:gosec // árvore própria, id validado
		if terr != nil {
			return res, errors.Join(err, terr)
		}
		if rep, terr = ParseSessionTSV(tsv, id); terr != nil {
			return res, errors.Join(err, terr)
		}
		res.FromTSV = true
	}
	if rep.TotalQuarantined > 0 || rep.QuarantineOn {
		return res, errors.New("o LMD informou quarentena ligada; a varredura foi descartada (o produto nunca move arquivos)")
	}
	res.Files = rep.TotalFiles
	for _, h := range rep.Hits {
		if h.Quarantined {
			return res, errors.New("o LMD informou arquivo em quarentena; a varredura foi descartada")
		}
		i, ok := FDIndex(h.File, pid, fds)
		if !ok {
			res.Unmapped++
			continue
		}
		res.Hits[i] = append(res.Hits[i], h)
	}
	if code == 2 && len(rep.Hits) == 0 {
		return res, errors.New("maldet indicou detecções, mas o relatório veio vazio")
	}
	return res, nil
}

func (s *Scanner) base() (string, error) {
	base := filepath.Join(s.Work, "base")
	if _, err := os.Lstat(filepath.Join(base, "internals")); err == nil {
		return base, nil
	}
	if err := os.MkdirAll(s.Work, 0o700); err != nil {
		return "", err
	}
	return PrepareBase(s.Work, s.Install)
}

func (s *Scanner) report(ctx context.Context, base, id string) (Report, error) {
	rctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	out := &limited{max: 256 << 20}
	errOut := &tail{max: 16 << 10}
	code, err := s.run(rctx, base, out, errOut, "--json-report", id)
	if err != nil {
		return Report{}, fmt.Errorf("maldet --json-report: %w", err)
	}
	if code != 0 || out.overflow {
		return Report{}, fmt.Errorf("maldet --json-report terminou com código %d: %s", code, cleanStderr(errOut.buf))
	}
	return ParseJSONReport(out.buf, id)
}

// run executa o maldet da instalação com a árvore-sombra e ambiente mínimo, num grupo de processos próprio
// (cancelar mata também os processos de análise que o maldet deixa em segundo plano).
func (s *Scanner) run(ctx context.Context, base string, stdout, stderr interface{ Write([]byte) (int, error) }, args ...string) (int, error) {
	cmd := exec.CommandContext(ctx, filepath.Join(s.Install.Dir, "maldet"), args...) //nolint:gosec // caminho fixo da instalação conferida; argumentos fixos
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if s.YRDir != "" {
		path = s.YRDir + ":" + path
	}
	cmd.Env = []string{"LMD_BASEDIR=" + base, "PATH=" + path, "HOME=" + s.Work, "LC_ALL=C", "LANG=C", "TERM=dumb"}
	cmd.Dir = s.Work
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && ctx.Err() == nil {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	// Processos de análise que sobrarem no grupo (o maldet já terminou) não podem ficar segurando os descritores.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	return 0, nil
}

// String ajuda nos logs.
func (r Result) String() string {
	n := 0
	for _, h := range r.Hits {
		n += len(h)
	}
	return "sessão " + r.ScanID + ", " + strconv.Itoa(r.Files) + " arquivos, " + strconv.Itoa(n) + " detecções"
}
