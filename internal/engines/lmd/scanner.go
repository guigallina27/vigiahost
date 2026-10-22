package lmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Scanner roda o maldet sobre lotes de arquivos já abertos.
type Scanner struct {
	Install Install
	// Work é um diretório gravável só do produto (o da execução): ali ficam a árvore-sombra (LMD_BASEDIR) com
	// tmp e sess próprios, as listas e os relatórios. A instalação do administrador não é alterada.
	Work string
	// YRDir é o diretório do yr do produto, posto à frente no PATH para o estágio YARA do LMD (rfxn.yara e regras
	// personalizadas do LMD). Vazio desliga o estágio YARA do LMD.
	YRDir string
	// Workers é o número de processos de análise do LMD (scan_workers); 0 deixa o automático do LMD.
	Workers int
	// Timeout por lote (padrão 1 h).
	Timeout time.Duration
}

// Result é o resultado de um lote: Hits[i] corresponde a files[i].
type Result struct {
	Hits   [][]Hit
	ScanID string
	// Files é quantos arquivos o LMD disse ter analisado.
	Files int
	// Unmapped conta detecções que citavam um caminho fora do lote (descartadas).
	Unmapped int
	// FromTSV indica que o relatório JSON falhou e a sessão foi lida pelo TSV.
	FromTSV bool
}

// Opções forçadas em toda execução (-co), por cima do conf.maldet do administrador. Desligam o que altera o
// servidor (quarentena, limpeza, suspensão de usuário), o estágio ClamAV (o produto já usa o clamd), alertas e
// estatísticas próprios (o produto notifica) e o gancho pós-varredura nas varreduras pela linha de comando.
func coOptions(yara bool, workers int) string {
	opts := []string{
		"quarantine_hits=0", "quarantine_clean=0", "quarantine_suspend_user=0", "quarantine_on_error=0",
		"scan_clamscan=0", "scan_clamd_remote=0",
		"email_alert=0", "email_panel_user_alerts=0", "slack_alert=0", "telegram_alert=0", "discord_alert=0",
		"enable_statistic=0", "post_scan_hook_on=digest", "scan_export_filelist=0",
	}
	if yara {
		opts = append(opts, "scan_yara=1")
	} else {
		opts = append(opts, "scan_yara=0")
	}
	if workers > 0 {
		opts = append(opts, fmt.Sprintf("scan_workers=%d", workers))
	}
	return strings.Join(opts, ",")
}

// Entradas da instalação que ganham diretório próprio na árvore-sombra; o resto vira link para a instalação.
var ownDirs = map[string]bool{"tmp": true, "sess": true, "pub": true, "quarantine": true}

// PrepareBase monta a árvore-sombra em work/base: links para a instalação (scripts, assinaturas, configuração do
// administrador) e tmp, sess e pub próprios. "quarantine" vira um arquivo comum, sem permissão: mesmo que alguma
// configuração escapasse do -co, mover um arquivo para a quarentena falharia.
func PrepareBase(work string, in Install) (string, error) {
	base := filepath.Join(work, "base")
	if err := os.RemoveAll(base); err != nil {
		return "", err
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	ents, err := os.ReadDir(in.Dir)
	if err != nil {
		return "", err
	}
	for _, e := range ents {
		if ownDirs[e.Name()] {
			continue
		}
		if err := os.Symlink(filepath.Join(in.Dir, e.Name()), filepath.Join(base, e.Name())); err != nil {
			return "", err
		}
	}
	for _, d := range []string{"tmp", "sess", "pub"} {
		if err := os.Mkdir(filepath.Join(base, d), 0o700); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(filepath.Join(base, "quarantine"), nil, 0o400); err != nil {
		return "", err
	}
	return base, nil
}

// resetSession esvazia tmp e sess entre lotes (cada lote é uma sessão nova do LMD).
func resetSession(base string) error {
	for _, d := range []string{"tmp", "sess"} {
		p := filepath.Join(base, d)
		if err := os.RemoveAll(p); err != nil {
			return err
		}
		if err := os.Mkdir(p, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// tail guarda só o fim da saída (a linha com o identificador da sessão vem no fim).
type tail struct {
	buf []byte
	max int
}

func (t *tail) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = append(t.buf[:0], t.buf[len(t.buf)-t.max:]...)
	}
	return len(p), nil
}

// limited guarda até max bytes e marca o excesso.
type limited struct {
	buf      []byte
	max      int
	overflow bool
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.max - len(l.buf); room > 0 {
		if len(p) > room {
			l.buf = append(l.buf, p[:room]...)
			l.overflow = true
		} else {
			l.buf = append(l.buf, p...)
		}
	} else if len(p) > 0 {
		l.overflow = true
	}
	return len(p), nil
}

// cleanStderr tira o ruído esperado da saída de erro (escrita recusada fora da árvore-sombra, pela unidade só
// leitura) e devolve as últimas linhas úteis para o diagnóstico.
func cleanStderr(b []byte) string {
	var keep []string
	for line := range strings.Lines(string(b)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "Read-only file system") || strings.HasPrefix(line, "chmod: ") {
			continue
		}
		keep = append(keep, line)
	}
	if len(keep) > 5 {
		keep = keep[len(keep)-5:]
	}
	return clip(strings.Join(keep, "; "), 1024)
}
