package pkgverify

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"sort"
	"strings"
)

// Alterações que a verificação aponta, na ordem das colunas do "rpm -V" (SM5DLUGTP), mais "missing".
const (
	ChangeSize    = "size"
	ChangeMode    = "mode"
	ChangeDigest  = "digest"
	ChangeDevice  = "device"
	ChangeLink    = "link"
	ChangeUser    = "user"
	ChangeGroup   = "group"
	ChangeMtime   = "mtime"
	ChangeCaps    = "capabilities"
	ChangeMissing = "missing"
)

var flagColumns = []struct {
	letter byte
	name   string
}{{'S', ChangeSize}, {'M', ChangeMode}, {'5', ChangeDigest}, {'D', ChangeDevice}, {'L', ChangeLink},
	{'U', ChangeUser}, {'G', ChangeGroup}, {'T', ChangeMtime}, {'P', ChangeCaps}}

// Issue é um arquivo de pacote que não confere com o banco de pacotes.
type Issue struct {
	Path string `json:"path"`
	// Flags é a marca como a ferramenta mostrou ("SM5....T.", "??5??????" ou "missing").
	Flags   string   `json:"flags"`
	Changes []string `json:"changes"`
	Config  bool     `json:"config,omitempty"`
	Doc     bool     `json:"doc,omitempty"`
	Ghost   bool     `json:"ghost,omitempty"`
	// Packages são os donos do arquivo (o rpm -V e o dpkg --verify não dizem; o debsums diz).
	Packages []Package `json:"packages,omitempty"`
	// Source é a ferramenta que apontou: rpm, dpkg ou debsums.
	Source string `json:"source"`
}

// Has diz se a alteração está na lista.
func (i Issue) Has(change string) bool {
	for _, c := range i.Changes {
		if c == change {
			return true
		}
	}
	return false
}

// ContentChanged indica conteúdo diferente do pacote (resumo ou tamanho).
func (i Issue) ContentChanged() bool { return i.Has(ChangeDigest) || i.Has(ChangeSize) }

// parseFlags converte a coluna de 9 posições; "?" (não conferido) e "." (confere) não viram alteração.
func parseFlags(f string) ([]string, bool) {
	if f == "missing" {
		return []string{ChangeMissing}, true
	}
	if len(f) != len(flagColumns) {
		return nil, false
	}
	var out []string
	for i, c := range flagColumns {
		switch f[i] {
		case '.', '?':
		case c.letter:
			out = append(out, c.name)
		default:
			return nil, false
		}
	}
	return out, true
}

// ParseVerify interpreta a saída do "rpm -V"/"rpm -Va" e do "dpkg --verify" (mesmo formato: 9 colunas de marcas
// ou "missing", o atributo do arquivo — c configuração, d documentação, g fantasma, l licença, r leia-me — e o
// caminho). Devolve as linhas que não reconheceu (avisos da ferramenta, dependências) separadas.
func ParseVerify(out []byte, source string) (issues []Issue, unparsed []string) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		flags, rest, ok := strings.Cut(line, " ")
		if !ok {
			unparsed = append(unparsed, line)
			continue
		}
		changes, ok := parseFlags(flags)
		if !ok {
			unparsed = append(unparsed, line)
			continue
		}
		rest = strings.TrimLeft(rest, " ")
		attr := byte(' ')
		if len(rest) >= 3 && rest[1] == ' ' && rest[2] == '/' && strings.IndexByte("cdglrma", rest[0]) >= 0 {
			attr, rest = rest[0], rest[2:]
		}
		if !strings.HasPrefix(rest, "/") {
			unparsed = append(unparsed, line)
			continue
		}
		issues = append(issues, Issue{Path: rest, Flags: flags, Changes: changes, Config: attr == 'c',
			Doc: attr == 'd' || attr == 'l' || attr == 'r', Ghost: attr == 'g', Source: source})
	}
	return issues, unparsed
}

// ParseDebsums interpreta as mensagens do "debsums -s" ("debsums: changed file /x (from pkg package)" e "missing
// file"), que saem no erro padrão. Configurações só aparecem com -a.
func ParseDebsums(text string) (issues []Issue, unparsed []string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		msg, ok := strings.CutPrefix(line, "debsums: ")
		if !ok {
			unparsed = append(unparsed, line)
			continue
		}
		var change string
		switch {
		case strings.HasPrefix(msg, "changed file "):
			change, msg = ChangeDigest, strings.TrimPrefix(msg, "changed file ")
		case strings.HasPrefix(msg, "missing file "):
			change, msg = ChangeMissing, strings.TrimPrefix(msg, "missing file ")
		default:
			unparsed = append(unparsed, line)
			continue
		}
		path, pkg := msg, ""
		if i := strings.LastIndex(msg, " (from "); i > 0 && strings.HasSuffix(msg, " package)") {
			path, pkg = msg[:i], strings.TrimSuffix(msg[i+len(" (from "):], " package)")
		}
		if !strings.HasPrefix(path, "/") {
			unparsed = append(unparsed, line)
			continue
		}
		is := Issue{Path: path, Changes: []string{change}, Source: "debsums", Flags: "??5??????"}
		if change == ChangeMissing {
			is.Flags = "missing"
		}
		if pkg != "" {
			name, arch, _ := strings.Cut(pkg, ":")
			is.Packages = []Package{{Name: name, Arch: arch}}
		}
		issues = append(issues, is)
	}
	return issues, unparsed
}

// VerifyResult é o resultado da verificação de todos os pacotes.
type VerifyResult struct {
	Manager Manager `json:"manager"`
	Issues  []Issue `json:"issues"`
	// Tools são as ferramentas que rodaram ("rpm -Va", "dpkg --verify", "debsums").
	Tools []string `json:"tools"`
	// DebsumsAvailable só vale no dpkg: o debsums é opcional e acrescenta o pacote de cada arquivo.
	DebsumsAvailable bool     `json:"debsums_available"`
	Warnings         []string `json:"warnings,omitempty"`
}

// maxVerifyOutput limita a saída aceita do rpm -Va / dpkg --verify (um sistema muito alterado ainda cabe).
const maxVerifyOutput = 64 << 20

// Verify confere todos os pacotes instalados (rpm -Va ou dpkg --verify e, se instalado, debsums) e atribui cada
// arquivo ao pacote dono.
func (v *Verifier) Verify(ctx context.Context) (VerifyResult, error) {
	res := VerifyResult{Manager: v.Manager}
	if err := v.check(); err != nil {
		return res, err
	}
	var issues []Issue
	switch v.Manager {
	case RPM:
		// --nodeps/--noscripts: só arquivos, sem dependências nem scripts de verificação dos pacotes.
		out, stderr, code, err := run(ctx, v.runner(), maxVerifyOutput, rpmBin, "-Va", "--nodeps", "--noscripts")
		if err != nil {
			return res, err
		}
		var unparsed []string
		issues, unparsed = ParseVerify(out, "rpm")
		res.Tools = append(res.Tools, "rpm -Va")
		res.Warnings = append(res.Warnings, toolWarnings(stderr, unparsed)...)
		// Código 1 significa "há diferenças"; outros códigos sem nenhuma linha reconhecida são falha da ferramenta.
		if code > 1 && len(issues) == 0 {
			return res, describeExit(rpmBin, code, stderr)
		}
	case DPKG:
		out, stderr, code, err := run(ctx, v.runner(), maxVerifyOutput, dpkgBin, "--verify")
		if err != nil {
			return res, err
		}
		var unparsed []string
		issues, unparsed = ParseVerify(out, "dpkg")
		res.Tools = append(res.Tools, "dpkg --verify")
		res.Warnings = append(res.Warnings, toolWarnings(stderr, unparsed)...)
		if code != 0 && len(issues) == 0 {
			return res, describeExit(dpkgBin, code, stderr)
		}
		if _, err := os.Stat(debsumsBin); err == nil {
			res.DebsumsAvailable = true
			// -a inclui as configurações; -s só relata problemas (no erro padrão).
			_, stderr, _, err := run(ctx, v.runner(), 1<<20, debsumsBin, "-a", "-s")
			if err != nil {
				return res, err
			}
			extra, unparsed := ParseDebsums(stderr)
			issues = mergeIssues(issues, extra)
			res.Tools = append(res.Tools, "debsums")
			res.Warnings = append(res.Warnings, toolWarnings("", unparsed)...)
		}
	}
	if err := v.attribute(ctx, issues); err != nil {
		res.Warnings = append(res.Warnings, "dono dos arquivos não identificado: "+err.Error())
	}
	sort.Slice(issues, func(i, j int) bool { return issues[i].Path < issues[j].Path })
	res.Issues = issues
	return res, nil
}

// mergeIssues une o dpkg --verify e o debsums pelo caminho: o debsums acrescenta o pacote e o que o outro não viu.
func mergeIssues(base, extra []Issue) []Issue {
	idx := make(map[string]int, len(base))
	for i, is := range base {
		idx[is.Path] = i
	}
	for _, e := range extra {
		i, ok := idx[e.Path]
		if !ok {
			idx[e.Path] = len(base)
			base = append(base, e)
			continue
		}
		if len(base[i].Packages) == 0 {
			base[i].Packages = e.Packages
		}
		for _, c := range e.Changes {
			if !base[i].Has(c) {
				base[i].Changes = append(base[i].Changes, c)
			}
		}
	}
	return base
}

// attribute preenche os donos dos arquivos que a ferramenta não informou.
func (v *Verifier) attribute(ctx context.Context, issues []Issue) error {
	var paths []string
	for _, is := range issues {
		if len(is.Packages) == 0 || is.Packages[0].Version == "" {
			paths = append(paths, is.Path)
		}
	}
	if len(paths) == 0 {
		return nil
	}
	owners, err := v.Owners(ctx, paths)
	if err != nil {
		return err
	}
	for i := range issues {
		if o := owners[issues[i].Path]; len(o) > 0 {
			issues[i].Packages = o
		}
	}
	return nil
}

// toolWarnings junta o erro padrão e as linhas não reconhecidas, com limite.
func toolWarnings(stderr string, unparsed []string) []string {
	var out []string
	for _, l := range append(strings.Split(stderr, "\n"), unparsed...) {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if len(out) == 20 {
			out = append(out, "(mais mensagens omitidas)")
			break
		}
		if len(l) > 300 {
			l = l[:300] + "…"
		}
		out = append(out, l)
	}
	return out
}
