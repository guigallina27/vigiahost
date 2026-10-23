package inspect

import (
	"fmt"
	"path"
	"strings"

	"github.com/guigallina27/vigiahost/internal/report"
)

// ProcHit é uma regra de processo ou rede que casou.
type ProcHit struct {
	Signature   string
	Severity    report.Severity
	Category    report.Category
	Description string
	Proc        *Process
	Evidence    map[string]string
}

var (
	tempDirs    = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}
	homeDirs    = []string{"/home/", "/root/", "/var/www/", "/srv/"}
	systemDirs  = []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/", "/usr/libexec/"}
	webParents  = []string{"httpd", "apache2", "nginx", "php-fpm", "lsphp", "litespeed", "lshttpd", "caddy", "php-cgi"}
	shellLike   = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "csh": true, "tcsh": true, "python": true, "python2": true, "python3": true, "perl": true, "ruby": true, "nc": true, "ncat": true, "socat": true, "telnet": true, "wget": true, "curl": true}
	mailHelpers = []string{"sendmail", "exim", "postdrop", "qmail", "msmtp", "ssmtp"}
	// Runtimes que costumam usar muita CPU legitimamente em hospedagem.
	busyRuntimes = []string{"php", "lsphp", "node", "python", "java", "ruby", "mysqld", "mariadbd", "httpd", "nginx"}
)

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// exePath tira o sufixo " (deleted)".
func exePath(exe string) string { return strings.TrimSuffix(exe, " (deleted)") }

// ClassifyExe marca memfd e apagado a partir do alvo de /proc/PID/exe.
func ClassifyExe(p *Process) {
	p.ExeDeleted = strings.HasSuffix(p.Exe, " (deleted)")
	p.ExeMemfd = strings.HasPrefix(p.Exe, "/memfd:")
}

// AnalyzeProcesses aplica as heurísticas da seção 8 do escopo à lista completa (precisa dos pais).
func AnalyzeProcesses(procs []*Process, uidMin int) []ProcHit {
	byPID := make(map[int]*Process, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}
	var hits []ProcHit
	add := func(p *Process, sig string, sev report.Severity, cat report.Category, desc string, ev map[string]string) {
		p.Flags = append(p.Flags, sig)
		hits = append(hits, ProcHit{Signature: sig, Severity: sev, Category: cat, Description: desc, Proc: p, Evidence: ev})
	}
	for _, p := range procs {
		exe := exePath(p.Exe)
		noFile := p.ExeMemfd || (p.ExeDeleted && !hasAnyPrefix(exe, systemDirs))
		switch {
		case p.ExeMemfd:
			add(p, "processo.executavel_memfd", report.SeverityCritical, report.CategoryProcess,
				"processo roda de um arquivo só em memória (memfd), sem nada no disco", nil)
		case p.ExeDeleted && hasAnyPrefix(exe, systemDirs):
			add(p, "processo.binario_substituido", report.SeverityInfo, report.CategoryProcess,
				"serviço roda um binário do sistema já substituído (atualização de pacote aguardando reinício)", nil)
		case p.ExeDeleted:
			add(p, "processo.executavel_apagado", report.SeverityHigh, report.CategoryProcess,
				"processo roda de um arquivo apagado do disco depois de iniciado", nil)
		}
		if !p.ExeMemfd && hasAnyPrefix(exe, tempDirs) {
			add(p, "processo.executavel_em_temporario", report.SeverityHigh, report.CategoryProcess,
				"executável em diretório temporário ("+path.Dir(exe)+")", nil)
		} else if !p.ExeMemfd && hasAnyPrefix(exe, homeDirs) && p.UID >= uint32(uidMin) { //nolint:gosec // UID_MIN é pequeno
			add(p, "processo.executavel_de_conta", report.SeverityLow, report.CategoryProcess,
				"processo de conta roda executável próprio (fora dos diretórios do sistema)", nil)
		}
		if p.kthreadArg && p.Exe != "" {
			add(p, "processo.imita_thread_do_kernel", report.SeverityCritical, report.CategoryProcess,
				"nome entre colchetes imita thread do kernel, mas o processo tem executável", map[string]string{"argv0": first(p.Cmdline)})
		}
		if p.ldPreload != "" {
			add(p, "processo.ld_preload", report.SeverityHigh, report.CategoryProcess,
				"LD_PRELOAD no ambiente injeta biblioteca no processo", map[string]string{"ld_preload": clipText(p.ldPreload, 512)})
		}
		if shellLike[p.Comm] && !containsAny(strings.Join(p.Cmdline, " "), mailHelpers) {
			for anc, depth := byPID[p.PPID], 0; anc != nil && depth < 4; anc, depth = byPID[anc.PPID], depth+1 {
				if hasAnyPrefix(anc.Comm, webParents) {
					add(p, "processo.shell_filho_do_servidor_web", report.SeverityMedium, report.CategoryProcess,
						"servidor web ou PHP originou shell/interpretador (indício de webshell em uso)",
						map[string]string{"ancestral": fmt.Sprintf("%s (PID %d)", anc.Comm, anc.PID)})
					break
				}
			}
		}
		if p.UID >= uint32(uidMin) && p.CPUPercent >= 80 && !hasAnyPrefix(p.Comm, busyRuntimes) { //nolint:gosec // idem
			add(p, "processo.cpu_alta_de_conta", report.SeverityMedium, report.CategoryProcess,
				"processo de conta com consumo alto de CPU (indício de mineração)",
				map[string]string{"cpu": fmt.Sprintf("%.0f%%", p.CPUPercent)})
		}
		if p.Package == "-" && hasAnyPrefix(exe, systemDirs) && !p.ExeDeleted {
			add(p, "processo.binario_de_sistema_fora_de_pacote", report.SeverityHigh, report.CategoryProcess,
				"binário em diretório do sistema que não pertence a nenhum pacote", nil)
		}
		if p.PackageStatus == "mismatch" && !p.ExeDeleted {
			add(p, "processo.binario_de_pacote_alterado", report.SeverityCritical, report.CategoryProcess,
				"processo roda binário de pacote cujo conteúdo não confere com o pacote instalado", p.packageEvidence)
		}
		// Rede.
		if noFile && (len(p.Listening) > 0 || len(p.Connected) > 0) {
			add(p, "rede.processo_sem_arquivo_com_rede", report.SeverityCritical, report.CategoryNetwork,
				"processo sem arquivo no disco com sockets de rede abertos", nil)
		}
		if len(p.Listening) > 0 && (hasAnyPrefix(exe, tempDirs) || p.ExeMemfd) {
			add(p, "rede.escuta_de_executavel_suspeito", report.SeverityHigh, report.CategoryNetwork,
				"executável de diretório temporário ou memória aceitando conexões", map[string]string{"escuta": strings.Join(p.Listening, ", ")})
		}
		for _, c := range p.Connected {
			if port := remotePort(c); minerPorts[port] {
				add(p, "rede.conexao_porta_de_mineracao", report.SeverityMedium, report.CategoryNetwork,
					"conexão de saída para porta típica de pool de mineração", map[string]string{"conexao": c})
				break
			}
		}
	}
	return hits
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func containsAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// remotePort extrai a porta remota de "tcp a:b->c:d".
func remotePort(conn string) int {
	_, remote, ok := strings.Cut(conn, "->")
	if !ok {
		return 0
	}
	i := strings.LastIndexByte(remote, ':')
	if i < 0 {
		return 0
	}
	var p int
	_, _ = fmt.Sscanf(remote[i+1:], "%d", &p)
	return p
}

// IsKernelThreadName indica argv[0] no formato de thread do kernel ("[kworker/0:1]").
func IsKernelThreadName(argv0 string) bool {
	return len(argv0) > 2 && strings.HasPrefix(argv0, "[") && strings.HasSuffix(argv0, "]")
}
