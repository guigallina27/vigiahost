package clamav

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Clamscan executa o clamscan para a fila de arquivos grandes (limites maiores que os do clamd) ou quando não há
// clamd. Como no yr, os arquivos chegam como /dev/fd/N e a saída só cita o descritor.
type Clamscan struct {
	Bin string
	// MaxFileBytes e MaxScanBytes elevam os limites padrão (100 MB e 400 MB); 0 mantém o padrão.
	MaxFileBytes int64
	MaxScanBytes int64
	// Database aponta outro diretório de assinaturas (opcional).
	Database string
}

// ClamscanVersion devolve a versão pelo clamscan --version.
func ClamscanVersion(ctx context.Context, bin string) (VersionInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	if err != nil {
		return VersionInfo{}, fmt.Errorf("clamscan --version: %w", err)
	}
	return ParseVersion(string(out)), nil
}

// ScanFiles analisa um lote; Verdicts[i] corresponde a files[i] (processo filho recebe files[i] como fd 3+i).
func (c *Clamscan) ScanFiles(ctx context.Context, files []*os.File) ([]Verdict, error) {
	out := make([]Verdict, len(files))
	if len(files) == 0 {
		return out, nil
	}
	args := []string{"--no-summary", "--stdout", "--file-list=/dev/stdin"}
	if c.MaxFileBytes > 0 {
		args = append(args, "--max-filesize="+strconv.FormatInt(c.MaxFileBytes, 10))
	}
	if c.MaxScanBytes > 0 {
		args = append(args, "--max-scansize="+strconv.FormatInt(c.MaxScanBytes, 10))
	}
	if c.Database != "" {
		args = append(args, "--database="+c.Database)
	}
	var list bytes.Buffer
	for i := range files {
		fmt.Fprintf(&list, "/dev/fd/%d\n", 3+i)
	}
	cmd := exec.CommandContext(ctx, c.Bin, args...) //nolint:gosec // binário descoberto em caminho fixo; argumentos fixos e só /dev/fd/N
	cmd.ExtraFiles = files
	cmd.Stdin = &list
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	// 0: nada encontrado; 1: algo encontrado; 2: erro (pode ser só de alguns arquivos).
	var exitErr *exec.ExitError
	if err != nil && (!errors.As(err, &exitErr) || exitErr.ExitCode() > 2) {
		return out, fmt.Errorf("clamscan: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	seen := make([]bool, len(files))
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		path, rest, ok := strings.Cut(sc.Text(), ": ")
		if !ok {
			continue
		}
		num, ok := strings.CutPrefix(path, "/dev/fd/")
		if !ok {
			continue
		}
		fd, convErr := strconv.Atoi(num)
		if convErr != nil || fd < 3 || fd-3 >= len(files) {
			continue
		}
		i := fd - 3
		seen[i] = true
		out[i] = ParseReply("x: " + rest)
	}
	if exitErr != nil && exitErr.ExitCode() == 2 {
		for i := range seen {
			if !seen[i] && out[i].Err == nil {
				out[i].Err = errors.New("clamscan não informou resultado para o arquivo")
			}
		}
	}
	return out, nil
}
