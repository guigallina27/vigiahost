package updates

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/version"
)

// Engine é o nome do "motor" nos achados e na cobertura.
const Engine = "updates"

// StaleCache é a idade a partir da qual o cache do gerenciador vira achado (a lista de correções pode estar
// incompleta).
const StaleCache = 7 * 24 * time.Hour

// Service é uma unidade systemd com processo que ainda usa arquivo substituído.
type Service struct {
	Unit   string   `json:"unit"`
	PIDs   []int    `json:"pids,omitempty"`
	Files  []string `json:"files,omitempty"`
	Source string   `json:"source"` // needs-restarting, needrestart ou maps
}

// Process é um processo fora de serviço (sessão, cron, contêiner) com arquivo substituído.
type Process struct {
	PID   int      `json:"pid"`
	Comm  string   `json:"comm"`
	UID   uint32   `json:"uid"`
	Files []string `json:"files"`
}

// Reboot diz se o sistema precisa reiniciar para usar o que foi atualizado.
type Reboot struct {
	// Known: houve como saber (kernel gerenciado por pacote, needs-restarting ou needrestart presentes).
	Known    bool     `json:"known"`
	Required bool     `json:"required"`
	Reasons  []string `json:"reasons,omitempty"`
	// RunningKernel é o kernel em uso; LatestKernel, o mais novo instalado por pacote.
	RunningKernel string   `json:"running_kernel"`
	LatestKernel  string   `json:"latest_kernel,omitempty"`
	Packages      []string `json:"packages,omitempty"`
}

// Report é o conteúdo de updates.json, mostrado na tela Atualizações do sistema.
type Report struct {
	Manager string `json:"manager"`
	// CacheUpdatedAt é a lista de pacotes mais recente no cache; CacheOldestAt, a mais antiga entre os repositórios.
	CacheUpdatedAt *time.Time `json:"cache_updated_at,omitempty"`
	CacheOldestAt  *time.Time `json:"cache_oldest_at,omitempty"`
	// RefreshAllowed reflete a configuração local do executor; Refreshed diz se esta execução atualizou a lista.
	RefreshAllowed bool              `json:"refresh_allowed"`
	Refreshed      bool              `json:"refreshed"`
	RefreshError   string            `json:"refresh_error,omitempty"`
	Security       []Update          `json:"security"`
	Other          []Update          `json:"other"`
	BySeverity     map[string]int    `json:"by_severity"`
	Reboot         Reboot            `json:"reboot"`
	Services       []Service         `json:"services"`
	Processes      []Process         `json:"processes"`
	Tools          map[string]bool   `json:"tools"`
	Error          string            `json:"error,omitempty"`
	Warnings       []string          `json:"warnings,omitempty"`
	Seconds        float64           `json:"seconds"`
	Notes          map[string]string `json:"notes,omitempty"`
}

// Findings transforma o relatório em achados do sistema. Cada condição é um achado só, que some (resolvido) quando
// a condição deixa de existir numa execução seguinte.
func Findings(rep Report, now time.Time) []report.Finding {
	var out []report.Finding
	add := func(sig, subject, desc string, sev report.Severity, ev map[string]string) {
		out = append(out, report.Finding{Engine: Engine, EngineVersion: version.Version, Signature: sig, Source: rep.Manager,
			Description: desc, Category: report.CategoryUpdate, Severity: sev, Subject: subject, Evidence: ev})
	}
	cacheAge := ""
	if rep.CacheUpdatedAt != nil {
		cacheAge = humanAge(now.Sub(*rep.CacheUpdatedAt))
	}
	if n := len(rep.Security); n > 0 {
		worst := ""
		names := make([]string, 0, min(n, 40))
		var advisories []string
		for i, u := range rep.Security {
			worst = worse(worst, u.Severity)
			if i < 40 {
				names = append(names, u.Name)
			}
			for _, a := range u.Advisories {
				if len(advisories) < 30 {
					advisories = appendUnique(advisories, a)
				}
			}
		}
		if n > 40 {
			names = append(names, fmt.Sprintf("e mais %d", n-40))
		}
		ev := map[string]string{"quantidade": strconv.Itoa(n), "pacotes": strings.Join(names, ", "),
			"por_gravidade": severityText(rep.BySeverity)}
		if len(advisories) > 0 {
			ev["avisos"] = strings.Join(advisories, ", ")
		}
		if cacheAge != "" {
			ev["lista_de_pacotes"] = "atualizada há " + cacheAge
		}
		add("atualizacao.correcoes_de_seguranca_pendentes", "security-updates",
			"pacotes com correção de segurança disponível e ainda não instalada", updateSeverity(worst), ev)
	}
	if rep.Reboot.Required {
		ev := map[string]string{"kernel_em_uso": rep.Reboot.RunningKernel}
		if rep.Reboot.LatestKernel != "" {
			ev["kernel_instalado"] = rep.Reboot.LatestKernel
		}
		if len(rep.Reboot.Reasons) > 0 {
			ev["motivos"] = strings.Join(rep.Reboot.Reasons, "; ")
		}
		if len(rep.Reboot.Packages) > 0 {
			ev["pacotes"] = strings.Join(rep.Reboot.Packages, ", ")
		}
		add("atualizacao.reinicio_pendente", "reboot",
			"atualização instalada só passa a valer depois de reiniciar o servidor (kernel ou bibliotecas centrais)",
			report.SeverityMedium, ev)
	}
	if n := len(rep.Services); n > 0 {
		units := make([]string, 0, min(n, 40))
		for i, s := range rep.Services {
			if i == 40 {
				units = append(units, fmt.Sprintf("e mais %d", n-40))
				break
			}
			units = append(units, s.Unit)
		}
		add("atualizacao.servicos_a_reiniciar", "services",
			"serviços ainda rodam com bibliotecas ou executáveis substituídos por atualização", report.SeverityLow,
			map[string]string{"quantidade": strconv.Itoa(n), "servicos": strings.Join(units, ", ")})
	}
	switch {
	case rep.Error == "" && rep.CacheUpdatedAt == nil && rep.Manager != "":
		add("atualizacao.lista_de_pacotes_ausente", "package-cache",
			"o gerenciador de pacotes não tem lista de pacotes baixada: correções pendentes não podem ser conferidas",
			report.SeverityLow, map[string]string{"gerenciador": rep.Manager})
	case rep.CacheUpdatedAt != nil && now.Sub(*rep.CacheUpdatedAt) > StaleCache:
		add("atualizacao.lista_de_pacotes_antiga", "package-cache",
			"a lista de pacotes do gerenciador está antiga: correções recentes podem não aparecer", report.SeverityLow,
			map[string]string{"atualizada_ha": cacheAge, "gerenciador": rep.Manager})
	}
	return out
}

// updateSeverity: aviso crítico vira alto; importante, médio; moderado e baixo, baixo; sem gravidade informada
// (APT), médio.
func updateSeverity(worst string) report.Severity {
	switch worst {
	case SevCritical:
		return report.SeverityHigh
	case SevImportant, SevUnknown:
		return report.SeverityMedium
	}
	return report.SeverityLow
}

// CountBySeverity conta as correções de segurança por gravidade.
func CountBySeverity(list []Update) map[string]int {
	out := map[string]int{}
	for _, u := range list {
		out[u.Severity]++
	}
	return out
}

func severityText(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return sevRank[keys[i]] < sevRank[keys[j]] })
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s: %d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d dias", int(d.Hours()/24))
}
