package scan

import (
	"strings"

	"github.com/guigallina27/vigiahost/internal/report"
)

// SourceRFXN é a fonte das assinaturas do Linux Malware Detect (R-fx Networks), venham do maldet ou do clamd que
// as carrega: a mesma fonte nos dois motores permite correlacionar as detecções (ADR-023).
const SourceRFXN = "rfxn"

// Prefixos com que o LMD nomeia as assinaturas ({HEX}php.cmdshell..., {MD5}..., {SHA256}..., {CSIG}..., {YARA}...).
var lmdPrefixes = []string{"{hex}", "{md5}", "{sha256}", "{csig}", "{yara}", "{cav}", "{sa}", "{strlen}"}

func lmdNamed(l string) bool {
	for _, p := range lmdPrefixes {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// ClamSource dá a fonte de uma assinatura do ClamAV: as do LMD copiadas para o clamd (rfxn.hdb, rfxn.ndb) chegam
// como "{HEX}...UNOFFICIAL"; as demais não oficiais, como clamav-unofficial.
func ClamSource(sig string) string {
	l := strings.ToLower(sig)
	switch {
	case lmdNamed(l):
		return SourceRFXN
	case strings.HasSuffix(sig, ".UNOFFICIAL"):
		return "clamav-unofficial"
	}
	return "clamav"
}

// ClassifyClamSignature dá categoria e severidade a partir do nome da assinatura.
func ClassifyClamSignature(sig string) (report.Category, report.Severity) {
	l := strings.ToLower(sig)
	switch {
	case strings.Contains(l, "eicar"):
		return report.CategoryTest, report.SeverityInfo
	case strings.HasPrefix(l, "heuristics.limits"):
		return report.CategorySuspicious, report.SeverityLow
	case strings.HasPrefix(l, "heuristics."):
		return report.CategorySuspicious, report.SeverityMedium
	case strings.HasPrefix(l, "pua."):
		return report.CategorySuspicious, report.SeverityLow
	case strings.Contains(l, "coinminer") || strings.Contains(l, "miner"):
		return report.CategoryMiner, report.SeverityHigh
	case strings.Contains(l, "webshell") || strings.Contains(l, "php.shell") || strings.Contains(l, "backdoor"):
		return report.CategoryWebshell, report.SeverityCritical
	case lmdNamed(l):
		return ClassifyLMDSignature(sig)
	}
	return report.CategoryMalware, report.SeverityHigh
}

// ClassifyLMDSignature dá categoria e severidade pelo nome da assinatura do LMD ({TIPO}linguagem.família.variante).
func ClassifyLMDSignature(sig string) (report.Category, report.Severity) {
	l := strings.ToLower(sig)
	if i := strings.IndexByte(l, '}'); i >= 0 {
		l = l[i+1:]
	}
	switch {
	case strings.Contains(l, "eicar"):
		return report.CategoryTest, report.SeverityInfo
	case strings.Contains(l, "miner"):
		return report.CategoryMiner, report.SeverityHigh
	case strings.Contains(l, "cmdshell") || strings.Contains(l, "webshell") || strings.Contains(l, "backdoor") ||
		strings.Contains(l, ".shell.") || strings.HasSuffix(l, ".shell"):
		return report.CategoryWebshell, report.SeverityCritical
	case strings.Contains(l, "generic") || strings.Contains(l, "unclassed") || strings.Contains(l, "suspicious"):
		// Famílias genéricas do LMD acusam padrões de injeção e ofuscação: forte indício, não certeza.
		return report.CategorySuspicious, report.SeverityHigh
	}
	return report.CategoryMalware, report.SeverityHigh
}
