// Package integrity é a execução "integrity": confere os arquivos de todos os pacotes instalados contra o banco do
// gerenciador (rpm -Va, dpkg --verify e debsums), as assinaturas de pacotes e repositórios, e transforma as
// diferenças em achados com gravidade pelo tipo de arquivo (escopo, seções 7.5 e 10). A consulta em si fica no
// pacote pkgverify, reutilizado pelo inspetor de processos e pela triagem do AIDE.
package integrity

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/guigallina27/vigiahost/internal/pkgverify"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/version"
)

// Engine é o nome do "motor" nos achados e na cobertura.
const Engine = "pkgverify"

// MaxFiles limita as diferenças guardadas no relatório (os achados não têm limite).
const MaxFiles = 2000

// FileResult é uma diferença que virou achado.
type FileResult struct {
	Path        string              `json:"path"`
	Flags       string              `json:"flags"`
	Changes     []string            `json:"changes"`
	Config      bool                `json:"config,omitempty"`
	Class       pkgverify.FileClass `json:"class"`
	Severity    report.Severity     `json:"severity"`
	Signature   string              `json:"signature"`
	Description string              `json:"description"`
	Packages    []pkgverify.Package `json:"packages,omitempty"`
	Algo        string              `json:"algo,omitempty"`
	Expected    string              `json:"expected,omitempty"`
	Actual      string              `json:"actual,omitempty"`
	SHA256      string              `json:"sha256,omitempty"`
}

// Report é o conteúdo de integrity.json, mostrado na tela Integridade.
type Report struct {
	Manager          pkgverify.Manager `json:"manager"`
	Tools            []string          `json:"tools"`
	DebsumsAvailable bool              `json:"debsums_available"`
	Packages         int               `json:"packages"`
	// Differences conta todas as linhas que a ferramenta apontou; Files guarda as que viraram achado.
	Differences int            `json:"differences"`
	Files       []FileResult   `json:"files"`
	Truncated   int            `json:"truncated,omitempty"`
	Ignored     map[string]int `json:"ignored"`
	// BySeverity conta as diferenças que viraram achado.
	BySeverity     map[report.Severity]int    `json:"by_severity"`
	Signatures     *pkgverify.SignatureReport `json:"signatures,omitempty"`
	SignatureError string                     `json:"signature_error,omitempty"`
	Error          string                     `json:"error,omitempty"`
	Warnings       []string                   `json:"warnings,omitempty"`
	Seconds        float64                    `json:"seconds"`
}

// StatFunc diz o que há no disco agora: a localização para o achado e o modo para a gravidade (nil se ausente).
type StatFunc func(path string) (*report.Location, *pkgverify.FileState)

// Assessed é uma diferença já avaliada.
type Assessed struct {
	Issue      pkgverify.Issue
	Assessment pkgverify.Assessment
	Location   *report.Location
}

// AssessAll avalia cada diferença e devolve as que viram achado, mais as contagens das ignoradas.
func AssessAll(issues []pkgverify.Issue, stat StatFunc) ([]Assessed, map[string]int) {
	ignored := map[string]int{}
	var out []Assessed
	for _, is := range issues {
		var loc *report.Location
		var st *pkgverify.FileState
		if stat != nil {
			loc, st = stat(is.Path)
		}
		a := pkgverify.Assess(is, st)
		if a.Ignored != "" {
			ignored[a.Ignored]++
			continue
		}
		out = append(out, Assessed{Issue: is, Assessment: a, Location: loc})
	}
	return out, ignored
}

// DigestPaths são os arquivos com conteúdo alterado que vale conferir contra o resumo registrado no pacote.
func DigestPaths(list []Assessed) []string {
	var out []string
	for _, a := range list {
		if a.Issue.ContentChanged() && a.Location != nil && len(out) < MaxFiles {
			out = append(out, a.Issue.Path)
		}
	}
	return out
}

var sevRank = map[report.Severity]int{report.SeverityCritical: 0, report.SeverityHigh: 1, report.SeverityMedium: 2,
	report.SeverityLow: 3, report.SeverityInfo: 4}

// FileFindings monta os achados e as linhas do relatório. A conferência do resumo (checks) acrescenta o resumo
// registrado no pacote e o calculado agora, e o SHA-256 que liga o achado ao objeto (cruzamento com os motores).
func FileFindings(manager pkgverify.Manager, list []Assessed, checks map[string]pkgverify.FileCheck) ([]report.Finding, []FileResult) {
	var findings []report.Finding
	var files []FileResult
	for _, a := range list {
		is, as := a.Issue, a.Assessment
		fr := FileResult{Path: is.Path, Flags: is.Flags, Changes: is.Changes, Config: is.Config, Class: as.Class,
			Severity: as.Severity, Signature: as.Signature, Description: as.Description, Packages: is.Packages}
		if c, ok := checks[is.Path]; ok {
			fr.Algo, fr.Expected, fr.Actual, fr.SHA256 = c.Algo, c.Expected, c.Actual, c.SHA256
			if len(fr.Packages) == 0 {
				fr.Packages = c.Packages
			}
		}
		ev := map[string]string{"alteracoes": pkgverify.ChangeLabels(is.Changes), "marcas": is.Flags, "ferramenta": is.Source,
			"tipo": string(as.Class)}
		if len(fr.Packages) > 0 {
			names := make([]string, 0, len(fr.Packages))
			for _, p := range fr.Packages {
				names = append(names, p.String())
			}
			ev["pacote"] = strings.Join(names, ", ")
		}
		if fr.Expected != "" {
			ev["resumo_esperado"] = fr.Algo + ":" + fr.Expected
		}
		if fr.Actual != "" {
			ev["resumo_atual"] = fr.Algo + ":" + fr.Actual
		}
		if is.Config {
			ev["configuracao"] = "sim"
		}
		f := report.Finding{Engine: Engine, EngineVersion: version.Version, Signature: as.Signature, Source: string(manager),
			Description: as.Description, Category: report.CategoryIntegrity, Severity: as.Severity, Evidence: ev}
		if a.Location != nil {
			loc := *a.Location
			f.Location = &loc
			if fr.SHA256 != "" {
				f.SHA256 = fr.SHA256
			}
		} else {
			f.Location = &report.Location{}
			f.Location.SetPath(is.Path)
		}
		findings = append(findings, f)
		files = append(files, fr)
	}
	sort.SliceStable(files, func(i, j int) bool {
		if sevRank[files[i].Severity] != sevRank[files[j].Severity] {
			return sevRank[files[i].Severity] < sevRank[files[j].Severity]
		}
		return files[i].Path < files[j].Path
	})
	return findings, files
}

// SignatureFindings transforma o relatório de assinaturas em achados do sistema (sem arquivo).
func SignatureFindings(sig pkgverify.SignatureReport) []report.Finding {
	var out []report.Finding
	base := func(sigName, subject, desc string, sev report.Severity, ev map[string]string) report.Finding {
		return report.Finding{Engine: Engine, EngineVersion: version.Version, Signature: sigName, Source: string(sig.Manager),
			Description: desc, Category: report.CategoryIntegrity, Severity: sev, Subject: subject, Evidence: ev}
	}
	if n := len(sig.Unsigned); n > 0 {
		out = append(out, base("integridade.pacotes_sem_assinatura", "pacotes-sem-assinatura",
			"pacotes instalados sem assinatura: a origem não pode ser conferida pelo gerenciador", report.SeverityLow,
			map[string]string{"quantidade": strconv.Itoa(n), "pacotes": packageList(sig.Unsigned, 40)}))
	}
	if n := len(sig.UnknownKey); n > 0 {
		pk := make([]pkgverify.Package, 0, n)
		keys := map[string]bool{}
		for _, k := range sig.UnknownKey {
			pk = append(pk, k.Package)
			keys[k.KeyID] = true
		}
		ids := make([]string, 0, len(keys))
		for k := range keys {
			ids = append(ids, k)
		}
		sort.Strings(ids)
		out = append(out, base("integridade.pacotes_chave_desconhecida", "pacotes-chave-desconhecida",
			"pacotes assinados por chave que não está importada no rpm (instalados sem conferência ou chave removida)",
			report.SeverityMedium, map[string]string{"quantidade": strconv.Itoa(n), "pacotes": packageList(pk, 40),
				"chaves": strings.Join(ids, ", ")}))
	}
	for _, r := range sig.Repos {
		if r.Problem == "" {
			continue
		}
		ev := map[string]string{"repositorio": r.ID, "arquivo": r.File, "problema": r.Problem}
		if r.Name != "" {
			ev["nome"] = r.Name
		}
		switch r.Problem {
		case pkgverify.RepoAptConfInsecure:
			out = append(out, base("integridade.apt_sem_autenticacao", "apt-conf",
				"configuração do APT aceita pacotes ou repositórios sem assinatura", report.SeverityHigh, ev))
		default:
			out = append(out, base("integridade.repositorio_sem_verificacao", "repo:"+r.ID,
				repoProblemText(r.Problem), report.SeverityMedium, ev))
		}
	}
	return out
}

func repoProblemText(p string) string {
	switch p {
	case pkgverify.RepoGPGCheckOff:
		return "repositório ativo sem gpgcheck: pacotes dele são instalados sem conferir a assinatura"
	case pkgverify.RepoTrusted:
		return "fonte do APT marcada como confiável (trusted=yes): o índice não tem a assinatura conferida"
	case pkgverify.RepoAllowInsecure:
		return "fonte do APT aceita repositório sem assinatura (allow-insecure)"
	case pkgverify.RepoUnsignedList:
		return "índice do repositório baixado sem assinatura (sem InRelease nem Release.gpg)"
	}
	return "repositório sem verificação de assinatura"
}

func packageList(list []pkgverify.Package, max int) string {
	names := make([]string, 0, min(len(list), max))
	for i, p := range list {
		if i == max {
			return strings.Join(names, ", ") + fmt.Sprintf(" e mais %d", len(list)-max)
		}
		names = append(names, p.String())
	}
	return strings.Join(names, ", ")
}

// CountSeverity conta as diferenças por gravidade.
func CountSeverity(files []FileResult) map[report.Severity]int {
	out := map[report.Severity]int{}
	for _, f := range files {
		out[f.Severity]++
	}
	return out
}
