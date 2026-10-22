// Package inspect implementa a inspeção somente leitura de processos, rede e persistência (escopo, seção 8),
// executada pelo executor dentro de uma unidade transitória ("vigiahost-executor inspect").
package inspect

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/guigallina27/vigiahost/internal/report"
)

// Engine é o nome do motor nos achados do inspetor.
const Engine = "inspector"

const maxConfigBytes = 1 << 20

// Item é uma entrada do inventário de persistência com o conteúdo lido (para as regras).
type Item struct {
	Entry   report.PersistenceEntry
	Content []byte
}

// Hit é uma regra de persistência que casou.
type Hit struct {
	Signature   string
	Severity    report.Severity
	Category    report.Category
	Description string
	Item        report.PersistenceEntry
	Evidence    map[string]string
}

// Padrões de conteúdo que indicam persistência maliciosa em scripts, cron, unidades e inicialização de shell.
var contentRules = []struct {
	sig  string
	sev  report.Severity
	desc string
	re   *regexp.Regexp
}{
	{"persistencia.download_e_execucao", report.SeverityHigh, "baixa conteúdo da rede e executa direto no shell",
		regexp.MustCompile(`(?i)\b(curl|wget|fetch)\b[^\n|;&]*\|\s*(ba|da|z|k)?sh\b`)},
	{"persistencia.base64_executado", report.SeverityHigh, "decodifica base64 e executa no shell",
		regexp.MustCompile(`(?i)base64\s+(-d|--decode)[^\n]*\|\s*(ba|da|z)?sh\b`)},
	{"persistencia.shell_reverso", report.SeverityCritical, "abre shell reverso (/dev/tcp, nc -e ou socket em python)",
		regexp.MustCompile(`(?i)(/dev/(tcp|udp)/[0-9a-z.\-]+/[0-9]+|\bnc(at)?\b[^\n]*\s-(e|c)\s|python[0-9.]*\s+-c\s+["'][^"'\n]*socket)`)},
	{"persistencia.execucao_em_temporario", report.SeverityHigh, "executa programa a partir de diretório temporário",
		regexp.MustCompile(`(^|[\s;'"=(&|])/(tmp|var/tmp|dev/shm)/\.?[A-Za-z0-9._\-]+(\s|$|;|&|\|)`)},
	{"persistencia.minerador", report.SeverityHigh, "referência a minerador de criptomoeda",
		regexp.MustCompile(`(?i)(xmrig|stratum\+tcp://|minerd\b|cpuminer|--donate-level)`)},
}

// kindsWithContentRules recebem as regras de conteúdo acima.
var kindsWithContentRules = map[string]bool{
	"cron": true, "systemd-unit": true, "systemd-user-unit": true, "rc-local": true, "init-d": true,
	"shell-init": true, "at-job": true, "systemd-generator": true, "udev-rule": true,
}

// Tipos sensíveis: mudança em relação ao inventário anterior vira achado.
var changeSeverity = map[string]report.Severity{
	"authorized-keys":   report.SeverityMedium,
	"ld-so-preload":     report.SeverityHigh,
	"pam":               report.SeverityMedium,
	"sudoers":           report.SeverityMedium,
	"systemd-unit":      report.SeverityLow,
	"systemd-user-unit": report.SeverityMedium,
	"cron":              report.SeverityLow,
	"sshd-config":       report.SeverityMedium,
	"shell-init":        report.SeverityLow,
	"ld-so-conf":        report.SeverityMedium,
	"udev-rule":         report.SeverityLow,
	"systemd-generator": report.SeverityMedium,
}

// Collector lê o inventário a partir de uma raiz (os.DirFS("/") em produção; mapa nos testes).
type Collector struct {
	Root  fs.FS
	Owner func(p string) string // dono do arquivo (opcional)
	// Homes são os diretórios pessoais a inspecionar (de /etc/passwd).
	Homes []string
	items []Item
	seen  map[string]bool
}

func rel(p string) string { return strings.TrimPrefix(path.Clean(p), "/") }

func (c *Collector) readFile(p string) ([]byte, bool) {
	f, err := c.Root.Open(rel(p))
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes))
	return b, err == nil
}

func (c *Collector) add(kind, p, detail string) {
	key := kind + "|" + p
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if c.seen[key] {
		return
	}
	b, ok := c.readFile(p)
	if !ok {
		return
	}
	c.seen[key] = true
	sum := sha256.Sum256(b)
	e := report.PersistenceEntry{Kind: kind, Path: p, Detail: detail, SHA256: hex.EncodeToString(sum[:])}
	if c.Owner != nil {
		e.Owner = c.Owner(p)
	}
	c.items = append(c.items, Item{Entry: e, Content: b})
}

// addDir acrescenta os arquivos regulares do diretório (sem descer, salvo recursive).
func (c *Collector) addDir(kind, dir string, recursive bool, filter func(name string) bool) {
	entries, err := fs.ReadDir(c.Root, rel(dir))
	if err != nil {
		return
	}
	for _, e := range entries {
		p := path.Join(dir, e.Name())
		switch {
		case e.IsDir():
			if recursive {
				c.addDir(kind, p, true, filter)
			}
		case e.Type().IsRegular() || e.Type()&fs.ModeSymlink != 0:
			if filter == nil || filter(e.Name()) {
				c.add(kind, p, "")
			}
		}
	}
}

func isUnitFile(name string) bool {
	for _, s := range []string{".service", ".timer", ".socket", ".path", ".mount"} {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// Collect percorre todos os pontos de persistência da seção 8 do escopo.
func (c *Collector) Collect() []Item {
	c.items, c.seen = nil, map[string]bool{}
	// systemd do sistema (só onde o administrador e os invasores escrevem; /usr/lib é do pacote).
	for _, d := range []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system"} {
		c.addDir("systemd-unit", d, true, isUnitFile)
	}
	c.addDir("systemd-user-unit", "/etc/systemd/user", true, isUnitFile)
	for _, d := range []string{"/etc/systemd/system-generators", "/usr/local/lib/systemd/system-generators",
		"/run/systemd/system-generators", "/etc/systemd/user-generators"} {
		c.addDir("systemd-generator", d, false, nil)
	}
	// cron e at.
	c.add("cron", "/etc/crontab", "")
	c.add("cron", "/etc/anacrontab", "")
	for _, d := range []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
		"/var/spool/cron", "/var/spool/cron/crontabs"} {
		c.addDir("cron", d, false, func(n string) bool { return !strings.HasPrefix(n, ".") })
	}
	for _, d := range []string{"/var/spool/at", "/var/spool/cron/atjobs"} {
		c.addDir("at-job", d, false, func(n string) bool { return !strings.HasPrefix(n, ".") })
	}
	// Inicialização clássica e de shell.
	c.add("rc-local", "/etc/rc.local", "")
	c.add("rc-local", "/etc/rc.d/rc.local", "")
	c.addDir("init-d", "/etc/init.d", false, nil)
	for _, p := range []string{"/etc/profile", "/etc/bashrc", "/etc/bash.bashrc", "/etc/zshrc", "/etc/environment"} {
		c.add("shell-init", p, "")
	}
	c.addDir("shell-init", "/etc/profile.d", false, nil)
	// Carregador dinâmico, PAM, SSH, sudo, udev.
	c.add("ld-so-preload", "/etc/ld.so.preload", "")
	c.add("ld-so-conf", "/etc/ld.so.conf", "")
	c.addDir("ld-so-conf", "/etc/ld.so.conf.d", false, nil)
	c.addDir("pam", "/etc/pam.d", false, nil)
	c.add("sshd-config", "/etc/ssh/sshd_config", "")
	c.addDir("sshd-config", "/etc/ssh/sshd_config.d", false, nil)
	c.add("sudoers", "/etc/sudoers", "")
	c.addDir("sudoers", "/etc/sudoers.d", false, nil)
	c.addDir("udev-rule", "/etc/udev/rules.d", false, func(n string) bool { return strings.HasSuffix(n, ".rules") })
	// Contas: chaves SSH, inicialização de shell e unidades de usuário.
	for _, h := range c.Homes {
		for _, f := range []string{".ssh/authorized_keys", ".ssh/authorized_keys2"} {
			c.add("authorized-keys", path.Join(h, f), "")
		}
		for _, f := range []string{".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".bash_logout"} {
			c.add("shell-init", path.Join(h, f), "")
		}
		c.addDir("systemd-user-unit", path.Join(h, ".config/systemd/user"), true, isUnitFile)
	}
	sort.Slice(c.items, func(i, j int) bool {
		if c.items[i].Entry.Kind != c.items[j].Entry.Kind {
			return c.items[i].Entry.Kind < c.items[j].Entry.Kind
		}
		return c.items[i].Entry.Path < c.items[j].Entry.Path
	})
	for i := range c.items {
		c.items[i].Entry.Detail = describe(c.items[i])
	}
	return c.items
}

// describe resume o item para a tela (ExecStart da unidade, número de chaves...).
func describe(it Item) string {
	switch it.Entry.Kind {
	case "systemd-unit", "systemd-user-unit":
		var execs []string
		for _, l := range lines(it.Content) {
			if k, v, ok := strings.Cut(l, "="); ok && strings.HasPrefix(strings.TrimSpace(k), "Exec") {
				execs = append(execs, strings.TrimSpace(v))
			}
		}
		return clipText(strings.Join(execs, " ; "), 512)
	case "authorized-keys":
		n := 0
		for _, l := range lines(it.Content) {
			if l != "" {
				n++
			}
		}
		return fmt.Sprintf("%d chave(s)", n)
	}
	return ""
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// lines devolve as linhas sem comentários e sem espaços nas pontas.
func lines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), maxConfigBytes)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		out = append(out, l)
	}
	return out
}

var (
	tempPath    = regexp.MustCompile(`(^|[\s"'=])/(tmp|var/tmp|dev/shm)/`)
	homeExec    = regexp.MustCompile(`(^|[\s"'=])/home/[^/\s]+/`)
	pamModule   = regexp.MustCompile(`^\s*-?(auth|account|password|session)\s+(\[[^\]]*\]|\S+)\s+(\S+)`)
	pamStdDir   = regexp.MustCompile(`^/(usr/)?lib(64)?/(x86_64-linux-gnu/|aarch64-linux-gnu/)?security/`)
	udevRun     = regexp.MustCompile(`RUN\+?=\s*"([^"]+)"`)
	nopasswdAll = regexp.MustCompile(`^\s*([^#\s]\S*)\s+.*NOPASSWD:\s*ALL\s*$`)
)

// Analyze aplica as regras ao inventário.
func Analyze(items []Item) []Hit {
	var hits []Hit
	add := func(it Item, sig string, sev report.Severity, desc string, ev map[string]string) {
		hits = append(hits, Hit{Signature: sig, Severity: sev, Category: report.CategoryPersistence, Description: desc,
			Item: it.Entry, Evidence: ev})
	}
	for _, it := range items {
		ls := lines(it.Content)
		// Conteúdo binário (gerador compilado, por exemplo) não passa pelas regras de texto: as cadeias soltas de um
		// executável casariam por acaso.
		if kindsWithContentRules[it.Entry.Kind] && !bytes.Contains(it.Content[:min(len(it.Content), 8192)], []byte{0}) {
			for _, r := range contentRules {
				for _, l := range ls {
					if r.re.MatchString(l) {
						add(it, r.sig, r.sev, r.desc, map[string]string{"linha": clipText(l, 512)})
						break
					}
				}
			}
		}
		switch it.Entry.Kind {
		case "systemd-unit", "systemd-user-unit":
			for _, l := range ls {
				k, v, ok := strings.Cut(l, "=")
				if !ok || !strings.HasPrefix(strings.TrimSpace(k), "Exec") {
					continue
				}
				if tempPath.MatchString(v) {
					add(it, "persistencia.unidade_executa_de_temporario", report.SeverityHigh,
						"unidade systemd executa programa de diretório temporário", map[string]string{"linha": clipText(l, 512)})
					break
				}
				if it.Entry.Kind == "systemd-unit" && homeExec.MatchString(v) {
					add(it, "persistencia.unidade_executa_de_conta", report.SeverityMedium,
						"unidade do sistema executa programa de diretório pessoal", map[string]string{"linha": clipText(l, 512)})
					break
				}
			}
		case "systemd-generator":
			add(it, "persistencia.gerador_systemd", report.SeverityMedium,
				"gerador do systemd fora do pacote (roda a cada boot, antes das unidades)", nil)
		case "at-job":
			add(it, "persistencia.tarefa_at", report.SeverityLow, "tarefa agendada pelo at", nil)
		case "ld-so-preload":
			if len(ls) > 0 {
				add(it, "persistencia.ld_so_preload", report.SeverityCritical,
					"biblioteca carregada em todos os processos por /etc/ld.so.preload (técnica comum de rootkit)",
					map[string]string{"conteudo": clipText(strings.Join(ls, " "), 512)})
			}
		case "ld-so-conf":
			for _, l := range ls {
				if tempPath.MatchString(" "+l) || homeExec.MatchString(" "+l) {
					add(it, "persistencia.ld_so_conf_suspeito", report.SeverityHigh,
						"caminho de bibliotecas em diretório temporário ou pessoal", map[string]string{"linha": l})
					break
				}
			}
		case "pam":
			for _, l := range ls {
				m := pamModule.FindStringSubmatch(l)
				if m == nil {
					continue
				}
				mod := m[3]
				switch {
				case strings.HasPrefix(mod, "/") && !pamStdDir.MatchString(mod):
					add(it, "persistencia.pam_modulo_fora_do_padrao", report.SeverityHigh,
						"módulo PAM carregado de caminho fora dos diretórios do sistema", map[string]string{"linha": l})
				case strings.Contains(mod, "pam_exec.so"):
					add(it, "persistencia.pam_exec", report.SeverityMedium,
						"pam_exec executa programa a cada autenticação (pode capturar senhas)", map[string]string{"linha": l})
				}
			}
		case "sshd-config":
			for _, l := range ls {
				f := strings.Fields(l)
				if len(f) >= 2 && strings.EqualFold(f[0], "AuthorizedKeysCommand") && !strings.EqualFold(f[1], "none") {
					add(it, "persistencia.ssh_authorized_keys_command", report.SeverityMedium,
						"o sshd consulta chaves por um comando externo", map[string]string{"linha": l})
				}
			}
		case "authorized-keys":
			for _, l := range ls {
				if strings.Contains(l, `command="`) {
					cmd := l[strings.Index(l, `command="`)+9:]
					if i := strings.Index(cmd, `"`); i >= 0 {
						cmd = cmd[:i]
					}
					for _, r := range contentRules {
						if r.re.MatchString(cmd) {
							add(it, "persistencia.chave_ssh_com_comando", report.SeverityHigh,
								"chave SSH com comando forçado suspeito", map[string]string{"comando": clipText(cmd, 512)})
							break
						}
					}
				}
			}
		case "sudoers":
			for _, l := range ls {
				if m := nopasswdAll.FindStringSubmatch(l); m != nil && m[1] != "root" && m[1] != "%wheel" && m[1] != "%sudo" && m[1] != "%admin" {
					add(it, "persistencia.sudo_sem_senha", report.SeverityLow,
						"permissão total de sudo sem senha", map[string]string{"linha": l})
				}
			}
		case "udev-rule":
			for _, l := range ls {
				for _, m := range udevRun.FindAllStringSubmatch(l, -1) {
					if tempPath.MatchString(" "+m[1]) || homeExec.MatchString(" "+m[1]) {
						add(it, "persistencia.udev_executa_de_temporario", report.SeverityHigh,
							"regra do udev executa programa de diretório temporário ou pessoal", map[string]string{"linha": l})
					}
				}
			}
		}
	}
	return hits
}

// Diff compara com o inventário anterior (tipo|caminho → hash), marca Change nos itens e devolve os removidos.
// Sem inventário anterior (primeira execução) nada é marcado: o atual vira a referência.
func Diff(items []Item, prev map[string]string) (removed []report.PersistenceEntry) {
	if prev == nil {
		return nil
	}
	cur := map[string]bool{}
	for i := range items {
		key := items[i].Entry.Kind + "|" + items[i].Entry.Path
		cur[key] = true
		old, ok := prev[key]
		switch {
		case !ok:
			items[i].Entry.Change = "added"
		case old != items[i].Entry.SHA256:
			items[i].Entry.Change = "changed"
		}
	}
	keys := make([]string, 0, len(prev))
	for k := range prev {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !cur[k] {
			kind, p, _ := strings.Cut(k, "|")
			removed = append(removed, report.PersistenceEntry{Kind: kind, Path: p, Change: "removed"})
		}
	}
	return removed
}

// ChangeHits transforma mudanças em tipos sensíveis em achados.
func ChangeHits(items []Item, removed []report.PersistenceEntry) []Hit {
	var hits []Hit
	for _, it := range items {
		sev, ok := changeSeverity[it.Entry.Kind]
		if !ok || it.Entry.Change == "" {
			continue
		}
		verb := map[string]string{"added": "adicionado", "changed": "alterado"}[it.Entry.Change]
		hits = append(hits, Hit{Signature: "persistencia." + strings.ReplaceAll(it.Entry.Kind, "-", "_") + "_" + it.Entry.Change,
			Severity: sev, Category: report.CategoryPersistence, Item: it.Entry,
			Description: fmt.Sprintf("%s %s desde a inspeção anterior", kindLabel(it.Entry.Kind), verb)})
	}
	for _, r := range removed {
		if r.Kind == "authorized-keys" || r.Kind == "ld-so-preload" {
			continue // remoção de chave ou de preload não é indício de ataque
		}
		if _, ok := changeSeverity[r.Kind]; ok {
			hits = append(hits, Hit{Signature: "persistencia." + strings.ReplaceAll(r.Kind, "-", "_") + "_removed",
				Severity: report.SeverityInfo, Category: report.CategoryPersistence, Item: r,
				Description: kindLabel(r.Kind) + " removido desde a inspeção anterior"})
		}
	}
	return hits
}

func kindLabel(k string) string {
	labels := map[string]string{
		"authorized-keys": "arquivo de chaves SSH", "ld-so-preload": "/etc/ld.so.preload", "pam": "configuração do PAM",
		"sudoers": "regra do sudo", "systemd-unit": "unidade do systemd", "systemd-user-unit": "unidade de usuário do systemd",
		"cron": "tarefa do cron", "sshd-config": "configuração do sshd", "shell-init": "arquivo de inicialização de shell",
		"ld-so-conf": "configuração do carregador dinâmico", "udev-rule": "regra do udev", "systemd-generator": "gerador do systemd",
	}
	if l, ok := labels[k]; ok {
		return l
	}
	return k
}

// Inventory converte para o mapa guardado entre execuções.
func Inventory(items []Item) map[string]string {
	m := make(map[string]string, len(items))
	for _, it := range items {
		m[it.Entry.Kind+"|"+it.Entry.Path] = it.Entry.SHA256
	}
	return m
}

// Homes lê os diretórios pessoais de /etc/passwd: root e contas com UID a partir de uidMin.
func Homes(root fs.FS, uidMin int) []string {
	b, err := fs.ReadFile(root, "etc/passwd")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		var uid int
		if _, err := fmt.Sscanf(f[2], "%d", &uid); err != nil {
			continue
		}
		home := path.Clean(f[5])
		if (uid != 0 && uid < uidMin) || uid == 65534 || !strings.HasPrefix(home, "/") || home == "/" || seen[home] {
			continue
		}
		seen[home] = true
		out = append(out, home)
		if len(out) >= 20000 {
			break
		}
	}
	return out
}
