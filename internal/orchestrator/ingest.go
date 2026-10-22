package orchestrator

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/guigallina27/vigiahost/internal/report"
)

// Limites para o conteúdo do findings.ndjson: ele vem de um processo que lê arquivos das contas, então nomes de
// regra, caminhos e evidências são tratados como entrada não confiável.
const (
	maxLineBytes  = 1 << 20
	maxBatchBytes = 4 << 20
	maxBatchLines = 2000
	maxShort      = 256
	maxText       = 2048
	maxPath       = 4096
	maxEvidence   = 32
)

// readFindings lê achados completos a partir de offset e devolve o novo offset. Linha sem quebra no fim ainda está
// sendo escrita e fica para a próxima leitura; linha inválida é pulada e contada.
func readFindings(path string, offset int64) (list []report.Finding, next int64, bad int, err error) {
	f, err := os.Open(path) //nolint:gosec // diretório da execução, informado pelo executor
	if errors.Is(err, os.ErrNotExist) {
		return nil, offset, 0, nil
	}
	if err != nil {
		return nil, offset, 0, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, 0, err
	}
	buf := make([]byte, maxBatchBytes)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, offset, 0, err
	}
	data := buf[:n]
	next = offset
	for len(list) < maxBatchLines {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			if len(data) >= maxLineBytes {
				// Linha gigante sem fim neste bloco: descarta o bloco inteiro e segue.
				next += int64(len(data))
				bad++
			}
			break
		}
		line := data[:i]
		data = data[i+1:]
		next += int64(i + 1)
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if len(line) > maxLineBytes {
			bad++
			continue
		}
		var fd report.Finding
		if err := json.Unmarshal(line, &fd); err != nil || !sanitize(&fd) {
			bad++
			continue
		}
		list = append(list, fd)
	}
	return list, next, bad, nil
}

func clip(s string, n int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, string(utf8.RuneError))
	}
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// sanitize limita tamanhos e recusa achado sem o mínimo (motor e assinatura).
func sanitize(f *report.Finding) bool {
	f.Engine, f.Signature = clip(strings.TrimSpace(f.Engine), 64), clip(strings.TrimSpace(f.Signature), maxShort)
	if f.Engine == "" || f.Signature == "" {
		return false
	}
	f.EngineVersion, f.RulesVersion = clip(f.EngineVersion, 128), clip(f.RulesVersion, 128)
	f.Source, f.License, f.Author = clip(f.Source, maxShort), clip(f.License, maxShort), clip(f.Author, maxShort)
	f.Reference, f.Description = clip(f.Reference, maxText), clip(f.Description, maxText)
	f.Category, f.FileType = report.Category(clip(string(f.Category), 32)), clip(f.FileType, 32)
	if !report.ValidSeverity(f.Severity) {
		f.Severity = report.SeverityMedium
	}
	f.SHA256 = strings.ToLower(f.SHA256)
	if len(f.SHA256) != 64 || strings.Trim(f.SHA256, "0123456789abcdef") != "" {
		f.SHA256 = ""
	}
	if l := f.Location; l != nil {
		l.Path, l.PathHex = clip(l.Path, maxPath), clip(l.PathHex, 2*maxPath)
	}
	if len(f.Evidence) > maxEvidence {
		f.Evidence = nil
	}
	for k, v := range f.Evidence {
		if len(k) > 64 {
			delete(f.Evidence, k)
			continue
		}
		f.Evidence[k] = clip(v, maxText)
	}
	if p := f.Process; p != nil {
		p.Comm, p.Exe, p.Unit, p.Cgroup = clip(p.Comm, 64), clip(p.Exe, maxPath), clip(p.Unit, maxShort), clip(p.Cgroup, maxText)
		if len(p.Cmdline) > 64 {
			p.Cmdline = p.Cmdline[:64]
		}
		for i := range p.Cmdline {
			p.Cmdline[i] = clip(p.Cmdline[i], maxText)
		}
	}
	if p := f.Persistence; p != nil {
		p.Kind, p.Path, p.Detail = clip(p.Kind, 64), clip(p.Path, maxPath), clip(p.Detail, maxText)
	}
	return true
}
