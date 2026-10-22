package pkgverify

import (
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/guigallina27/vigiahost/internal/report"
)

// FileClass é o tipo do arquivo para decidir a gravidade da alteração.
type FileClass string

const (
	ClassBinary          FileClass = "binary"
	ClassLibrary         FileClass = "library"
	ClassPAM             FileClass = "pam_module"
	ClassKernelModule    FileClass = "kernel_module"
	ClassConfigSensitive FileClass = "config_sensitive"
	ClassConfig          FileClass = "config"
	ClassDoc             FileClass = "doc"
	ClassOther           FileClass = "other"
)

// Motivos para não virar achado (contados no relatório).
const (
	IgnoreDoc       = "doc"        // documentação, manual, licença (minimal e path-exclude apagam de propósito)
	IgnoreGhost     = "ghost"      // arquivo fantasma: o pacote só reserva o nome
	IgnoreMtimeOnly = "mtime_only" // só a data mudou, conteúdo igual
	IgnoreDirectory = "directory"  // metadados de diretório
	IgnoreUnchecked = "unchecked"  // a ferramenta não conseguiu conferir (marca "?")
)

var (
	binDirs = []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/local/bin/", "/usr/local/sbin/",
		"/usr/lib/systemd/", "/lib/systemd/", "/usr/lib/polkit-1/", "/usr/lib/openssh/", "/usr/lib/dbus-1.0/"}
	libDirs   = []string{"/lib/", "/lib64/", "/lib32/", "/usr/lib/", "/usr/lib64/", "/usr/lib32/", "/usr/libx32/", "/usr/local/lib/"}
	docDirs   = []string{"/usr/share/doc/", "/usr/share/man/", "/usr/share/info/", "/usr/share/licenses/", "/usr/share/gtk-doc/", "/usr/share/help/", "/usr/share/lintian/", "/usr/share/locale/"}
	pamModule = regexp.MustCompile(`^/(usr/)?lib(64|32)?/([a-z0-9_]+-linux-gnu[a-z0-9_]*/)?security/[^/]+\.so$`)
	kmodule   = regexp.MustCompile(`^/(usr/)?lib/modules/.+\.ko(\.(xz|zst|gz))?$`)
	loader    = regexp.MustCompile(`/ld-linux[^/]*\.so[^/]*$|/ld-musl[^/]*\.so[^/]*$|/ld64\.so[^/]*$`)
	codeExt   = []string{".py", ".pyc", ".pl", ".pm", ".rb", ".sh", ".lua", ".php", ".js", ".jar"}
	// Binários que rootkits de espaço de usuário costumam trocar e os de autenticação: alteração é crítica.
	criticalBins = map[string]bool{"ls": true, "ps": true, "netstat": true, "ss": true, "top": true, "lsof": true,
		"find": true, "du": true, "login": true, "sshd": true, "ssh": true, "su": true, "sudo": true, "passwd": true,
		"crond": true, "cron": true, "pidof": true, "pgrep": true, "w": true, "who": true, "last": true, "ifconfig": true,
		"ip": true, "kill": true, "pkill": true, "killall": true, "chkconfig": true, "systemctl": true, "bash": true,
		"sh": true, "dash": true, "tar": true, "rpm": true, "dpkg": true, "insmod": true, "modprobe": true, "lsmod": true}
	sensitiveConfig = []string{"/etc/pam.d/", "/etc/security/", "/etc/ssh/", "/etc/sudoers", "/etc/ld.so.", "/etc/profile",
		"/etc/bashrc", "/etc/bash.bashrc", "/etc/crontab", "/etc/cron.", "/etc/systemd/", "/etc/init.d/", "/etc/rc.d/",
		"/etc/nsswitch.conf", "/etc/hosts.allow", "/etc/hosts.deny", "/etc/login.defs", "/etc/environment", "/etc/shells"}
)

func hasPrefix(s string, list []string) bool {
	for _, p := range list {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// Classify devolve o tipo do arquivo pelo caminho e pela marca de configuração do pacote.
func Classify(p string, config bool) FileClass {
	switch {
	case pamModule.MatchString(p):
		return ClassPAM
	case kmodule.MatchString(p):
		return ClassKernelModule
	case config || strings.HasPrefix(p, "/etc/"):
		if hasPrefix(p, sensitiveConfig) {
			return ClassConfigSensitive
		}
		return ClassConfig
	case hasPrefix(p, docDirs):
		return ClassDoc
	case hasPrefix(p, binDirs) && !strings.Contains(path.Base(p), ".so"):
		return ClassBinary
	case hasPrefix(p, libDirs) && (strings.Contains(path.Base(p), ".so") || hasSuffix(p, codeExt)):
		return ClassLibrary
	case hasPrefix(p, libDirs) || strings.HasPrefix(p, "/usr/share/"):
		if hasSuffix(p, codeExt) {
			return ClassLibrary
		}
	}
	return ClassOther
}

func hasSuffix(s string, list []string) bool {
	for _, x := range list {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}

// FileState é o que se sabe do arquivo no disco agora (nil = ausente ou não conferido).
type FileState struct {
	Mode fs.FileMode
	// CapsKnown: deu para ler as capacidades do arquivo (security.capability); Caps: o arquivo tem alguma.
	CapsKnown bool
	Caps      bool
}

// Assessment é a decisão sobre uma diferença: se vira achado, com que assinatura e gravidade.
type Assessment struct {
	Class       FileClass       `json:"class"`
	Ignored     string          `json:"ignored,omitempty"`
	Signature   string          `json:"signature,omitempty"`
	Severity    report.Severity `json:"severity,omitempty"`
	Description string          `json:"description,omitempty"`
}

// Assess aplica a tabela de gravidade (escopo, seção 7.5): binários, bibliotecas e módulos PAM com conteúdo
// alterado são altos ou críticos; configuração alterada é informativa ou baixa; documentação e só data mudada não
// viram achado.
func Assess(is Issue, st *FileState) Assessment {
	a := Assessment{Class: Classify(is.Path, is.Config)}
	if is.Doc && !is.Config {
		a.Class = ClassDoc
	}
	switch {
	case is.Ghost:
		a.Ignored = IgnoreGhost
		return a
	case a.Class == ClassDoc:
		a.Ignored = IgnoreDoc
		return a
	case st != nil && st.Mode.IsDir() && !is.Has(ChangeMissing):
		a.Ignored = IgnoreDirectory
		return a
	}
	exec := a.Class == ClassBinary || a.Class == ClassLibrary || a.Class == ClassPAM || a.Class == ClassKernelModule
	critical := a.Class == ClassPAM || a.Class == ClassKernelModule || loader.MatchString(is.Path) ||
		(a.Class == ClassBinary && criticalBins[path.Base(is.Path)])
	set := func(sig string, sev report.Severity, desc string) Assessment {
		a.Signature, a.Severity, a.Description = sig, sev, desc
		return a
	}
	switch {
	case is.Has(ChangeMissing):
		switch {
		case exec:
			return set("integridade.arquivo_ausente", report.SeverityMedium,
				"arquivo executável ou biblioteca do pacote foi apagado")
		case a.Class == ClassConfig || a.Class == ClassConfigSensitive:
			return set("integridade.arquivo_ausente", report.SeverityInfo, "arquivo de configuração do pacote foi apagado")
		default:
			// Diretório de cache, documentação de idioma, /boot em contêiner: ausência comum e sem efeito na execução.
			return set("integridade.arquivo_ausente", report.SeverityInfo, "arquivo ou diretório do pacote foi apagado")
		}
	case is.ContentChanged():
		switch {
		case a.Class == ClassPAM:
			return set("integridade.modulo_pam_alterado", report.SeverityCritical,
				"módulo PAM diferente do pacote instalado (autenticação pode estar comprometida)")
		case a.Class == ClassKernelModule:
			return set("integridade.modulo_kernel_alterado", report.SeverityCritical, "módulo de kernel diferente do pacote instalado")
		case a.Class == ClassBinary && critical:
			return set("integridade.binario_alterado", report.SeverityCritical,
				"binário do sistema diferente do pacote instalado (alvo comum de rootkit)")
		case a.Class == ClassBinary:
			return set("integridade.binario_alterado", report.SeverityHigh, "binário do sistema diferente do pacote instalado")
		case a.Class == ClassLibrary && critical:
			return set("integridade.biblioteca_alterada", report.SeverityCritical, "carregador dinâmico diferente do pacote instalado")
		case a.Class == ClassLibrary:
			return set("integridade.biblioteca_alterada", report.SeverityHigh, "biblioteca ou código do sistema diferente do pacote instalado")
		case a.Class == ClassConfigSensitive:
			return set("integridade.configuracao_alterada", report.SeverityLow,
				"configuração de segurança alterada em relação ao pacote (confira se a mudança foi feita pela equipe)")
		case a.Class == ClassConfig:
			return set("integridade.configuracao_alterada", report.SeverityInfo, "configuração alterada em relação ao pacote")
		default:
			return set("integridade.arquivo_alterado", report.SeverityLow, "arquivo do pacote com conteúdo diferente")
		}
	case is.Has(ChangeLink):
		if exec {
			return set("integridade.link_alterado", report.SeverityHigh, "link simbólico de comando ou biblioteca aponta para outro destino")
		}
		return set("integridade.link_alterado", report.SeverityLow, "link simbólico do pacote aponta para outro destino")
	case is.Has(ChangeMode) || is.Has(ChangeUser) || is.Has(ChangeGroup) || is.Has(ChangeCaps) || is.Has(ChangeDevice):
		setid := st != nil && st.Mode&(fs.ModeSetuid|fs.ModeSetgid) != 0
		permsOnly := !is.Has(ChangeMode) && !is.Has(ChangeUser) && !is.Has(ChangeGroup) && !is.Has(ChangeDevice)
		switch {
		case exec && permsOnly && !setid && st != nil && st.CapsKnown && !st.Caps:
			// O pacote prevê capacidades que o arquivo não tem (cópia sem atributos estendidos, imagem de contêiner):
			// o programa ficou com menos privilégio, não com mais.
			return set("integridade.permissoes_alteradas", report.SeverityLow,
				"capacidades previstas no pacote ausentes no arquivo (o programa roda com menos privilégio)")
		case exec && (is.Has(ChangeCaps) || (setid && (is.Has(ChangeMode) || is.Has(ChangeUser) || is.Has(ChangeGroup)))):
			// Programa setuid/setgid com outro dono ou grupo concede outra identidade a quem o executa.
			return set("integridade.permissoes_alteradas", report.SeverityHigh,
				"permissões especiais (setuid, setgid ou capacidades) ou dono de programa setuid/setgid diferentes do pacote")
		case exec:
			return set("integridade.permissoes_alteradas", report.SeverityMedium, "dono ou permissões diferentes do pacote")
		case a.Class == ClassConfigSensitive:
			return set("integridade.permissoes_alteradas", report.SeverityLow, "dono ou permissões de configuração de segurança alterados")
		default:
			return set("integridade.permissoes_alteradas", report.SeverityInfo, "dono ou permissões diferentes do pacote")
		}
	case is.Has(ChangeMtime):
		a.Ignored = IgnoreMtimeOnly
		return a
	}
	a.Ignored = IgnoreUnchecked
	return a
}

// ChangeLabels traduz as alterações para o texto da evidência.
func ChangeLabels(changes []string) string {
	names := map[string]string{ChangeSize: "tamanho", ChangeMode: "permissões", ChangeDigest: "conteúdo",
		ChangeDevice: "dispositivo", ChangeLink: "destino do link", ChangeUser: "dono", ChangeGroup: "grupo",
		ChangeMtime: "data de modificação", ChangeCaps: "capacidades", ChangeMissing: "ausente"}
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		if n, ok := names[c]; ok {
			out = append(out, n)
		} else {
			out = append(out, c)
		}
	}
	return strings.Join(out, ", ")
}
