package inspect

import (
	"path"
	"regexp"
	"strings"
)

var (
	secretFlag   = regexp.MustCompile(`(?i)^--?(pass(word|wd)?|pwd|secret|token|api[-_]?key|access[-_]?key|auth([-_]?token)?|key)$`)
	secretAssign = regexp.MustCompile(`(?i)^((--?)?[a-z0-9_.\-]*(pass(word|wd)?|pwd|secret|token|api[-_]?key|access[-_]?key|auth[-_]?token)[a-z0-9_.\-]*=)(.+)$`)
	urlUserinfo  = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://[^/:@\s]+:)[^@/\s]+@`)
)

const mask = "****"

// MaskArgs esconde segredos da linha de comando antes de gravar a evidência (escopo, seção 8): valores de opções
// como --password e token=, senha em URL e o -pSENHA dos clientes MySQL.
func MaskArgs(args []string) []string {
	out := make([]string, len(args))
	mysql := len(args) > 0 && strings.Contains(path.Base(args[0]), "mysql") || len(args) > 0 && strings.Contains(path.Base(args[0]), "mariadb")
	for i, a := range args {
		switch {
		case i > 0 && secretFlag.MatchString(args[i-1]):
			out[i] = mask
		case secretAssign.MatchString(a):
			out[i] = secretAssign.ReplaceAllString(a, "${1}"+mask)
		case mysql && strings.HasPrefix(a, "-p") && len(a) > 2:
			out[i] = "-p" + mask
		default:
			out[i] = urlUserinfo.ReplaceAllString(a, "${1}"+mask+"@")
		}
		if len(out[i]) > 2048 {
			out[i] = out[i][:2048] + "…"
		}
	}
	return out
}
