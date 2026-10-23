package pkgverify

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Situação da assinatura de um pacote RPM instalado.
const (
	SigSigned     = "signed"      // assinado por uma chave importada no rpm
	SigUnknownKey = "unknown_key" // assinado por chave que não está importada (instalado com --nogpgcheck ou chave removida)
	SigUnsigned   = "unsigned"    // sem assinatura
)

// Problemas de repositório.
const (
	RepoGPGCheckOff     = "gpgcheck_off"      // repositório RPM ativo sem gpgcheck
	RepoTrusted         = "trusted"           // fonte APT marcada como confiável sem verificação (trusted=yes)
	RepoAllowInsecure   = "allow_insecure"    // fonte APT que aceita repositório sem assinatura
	RepoUnsignedList    = "unsigned_list"     // lista baixada sem InRelease nem Release.gpg
	RepoAptConfInsecure = "apt_conf_insecure" // apt.conf libera pacotes sem autenticação
)

// Key é uma chave pública importada no rpm.
type Key struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

// KeyedPackage é um pacote assinado por uma chave que não está importada.
type KeyedPackage struct {
	Package
	KeyID string `json:"key_id"`
}

// Repo é um repositório configurado e o que foi conferido nele.
type Repo struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	File    string `json:"file"`
	Enabled bool   `json:"enabled"`
	// Verified: o gerenciador confere a assinatura dos pacotes (RPM) ou do índice (APT) deste repositório.
	Verified bool   `json:"verified"`
	Problem  string `json:"problem,omitempty"`
}

// SignatureReport resume as assinaturas de pacotes e repositórios.
type SignatureReport struct {
	Manager Manager `json:"manager"`
	// Method: "package" no RPM (cada pacote tem assinatura própria, conferida na instalação); "repository" no dpkg
	// (a assinatura é do índice do repositório, conferida pelo APT ao baixar).
	Method     string         `json:"method"`
	Keys       []Key          `json:"keys,omitempty"`
	Signed     int            `json:"signed"`
	Unsigned   []Package      `json:"unsigned,omitempty"`
	UnknownKey []KeyedPackage `json:"unknown_key,omitempty"`
	Repos      []Repo         `json:"repos"`
	Warnings   []string       `json:"warnings,omitempty"`

	byPackage map[string]string
}

// rpmSigFormat: nome, época, versão, lançamento, arquitetura e as quatro formas de assinatura do cabeçalho.
const rpmSigFormat = `%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{RSAHEADER:pgpsig}\t%{DSAHEADER:pgpsig}\t%{SIGPGP:pgpsig}\t%{SIGGPG:pgpsig}\n`

var keyIDPattern = regexp.MustCompile(`Key ID ([0-9a-fA-F]{8,40})`)

// RPMSignature é a assinatura registrada de um pacote.
type RPMSignature struct {
	Package Package
	KeyID   string // vazio = sem assinatura
}

// ParseRPMSignatures lê a saída de "rpm -qa --qf rpmSigFormat". Os pacotes gpg-pubkey (as próprias chaves) ficam
// de fora.
func ParseRPMSignatures(out []byte) []RPMSignature {
	var list []RPMSignature
	for _, l := range splitLines(out) {
		f := strings.Split(l, "\t")
		if len(f) != 9 || f[0] == "gpg-pubkey" {
			continue
		}
		s := RPMSignature{Package: rpmPackage(f[0], f[1], f[2], f[3], f[4])}
		for _, sig := range f[5:] {
			if m := keyIDPattern.FindStringSubmatch(sig); m != nil {
				s.KeyID = strings.ToLower(m[1])
				break
			}
		}
		list = append(list, s)
	}
	return list
}

// ParseRPMPubkeys lê "rpm -q gpg-pubkey --qf '%{VERSION}\t%{RELEASE}\t%{SUMMARY}\n'".
func ParseRPMPubkeys(out []byte) []Key {
	var keys []Key
	for _, l := range splitLines(out) {
		f := strings.SplitN(l, "\t", 3)
		if len(f) != 3 || f[0] == "" || strings.Contains(l, "is not installed") {
			continue
		}
		keys = append(keys, Key{ID: strings.ToLower(f[0]), Summary: f[2]})
	}
	return keys
}

// keyKnown compara o ID do pacote (16 hex ou impressão digital) com as chaves importadas (8 hex no rpm 4.x).
func keyKnown(id string, keys []Key) bool {
	for _, k := range keys {
		if strings.HasSuffix(id, k.ID) || strings.HasSuffix(k.ID, id) {
			return true
		}
	}
	return false
}

// Signatures confere as assinaturas (resultado em cache).
func (v *Verifier) Signatures(ctx context.Context) (SignatureReport, error) {
	v.mu.Lock()
	if v.sigs != nil {
		r := *v.sigs
		v.mu.Unlock()
		return r, nil
	}
	v.mu.Unlock()
	rep := SignatureReport{Manager: v.Manager, Repos: []Repo{}}
	if err := v.check(); err != nil {
		return rep, err
	}
	switch v.Manager {
	case RPM:
		rep.Method = "package"
		out, stderr, code, err := run(ctx, v.runner(), 32<<20, rpmBin, "-qa", "--qf", rpmSigFormat)
		if err != nil {
			return rep, err
		}
		if code != 0 && len(out) == 0 {
			return rep, describeExit(rpmBin, code, stderr)
		}
		kout, _, _, err := run(ctx, v.runner(), 1<<20, rpmBin, "-q", "gpg-pubkey", "--qf", `%{VERSION}\t%{RELEASE}\t%{SUMMARY}\n`)
		if err != nil {
			return rep, err
		}
		rep.Keys = ParseRPMPubkeys(kout)
		classifyRPMSignatures(&rep, ParseRPMSignatures(out))
		rep.Repos = RPMRepos(v.root())
	case DPKG:
		rep.Method = "repository"
		rep.Repos = AptRepos(v.root())
	}
	v.mu.Lock()
	v.sigs = &rep
	v.mu.Unlock()
	return rep, nil
}

func classifyRPMSignatures(rep *SignatureReport, sigs []RPMSignature) {
	rep.byPackage = make(map[string]string, len(sigs))
	for _, s := range sigs {
		st := SigSigned
		switch {
		case s.KeyID == "":
			st = SigUnsigned
			rep.Unsigned = append(rep.Unsigned, s.Package)
		case !keyKnown(s.KeyID, rep.Keys):
			st = SigUnknownKey
			rep.UnknownKey = append(rep.UnknownKey, KeyedPackage{Package: s.Package, KeyID: s.KeyID})
		default:
			rep.Signed++
		}
		rep.byPackage[s.Package.String()] = st
	}
	sort.Slice(rep.Unsigned, func(i, j int) bool { return rep.Unsigned[i].Name < rep.Unsigned[j].Name })
	sort.Slice(rep.UnknownKey, func(i, j int) bool { return rep.UnknownKey[i].Name < rep.UnknownKey[j].Name })
}

// --- Repositórios RPM (dnf/yum) ---

func parseBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "yes", "true", "on":
		return true, true
	case "0", "no", "false", "off":
		return false, true
	}
	return false, false
}

// parseINI lê seções e chaves de um arquivo .repo/.conf (sem interpolar variáveis).
func parseINI(r io.Reader) map[string]map[string]string {
	out := map[string]map[string]string{}
	sec := ""
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			sec = strings.TrimSpace(l[1 : len(l)-1])
			if out[sec] == nil {
				out[sec] = map[string]string{}
			}
			continue
		}
		k, val, ok := strings.Cut(l, "=")
		if !ok || sec == "" {
			continue
		}
		out[sec][strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(val)
	}
	return out
}

// RPMRepos lê /etc/yum.repos.d/*.repo e o gpgcheck padrão do dnf.conf (ou yum.conf). Sem gpgcheck em nenhum dos
// dois, o padrão do dnf é não conferir.
func RPMRepos(root string) []Repo {
	defGPG := false
	for _, conf := range []string{"etc/dnf/dnf.conf", "etc/yum.conf"} {
		f, err := os.Open(filepath.Join(root, conf)) //nolint:gosec // configuração do sistema
		if err != nil {
			continue
		}
		ini := parseINI(f)
		_ = f.Close()
		if b, ok := parseBool(ini["main"]["gpgcheck"]); ok {
			defGPG = b
		}
		break
	}
	files, _ := filepath.Glob(filepath.Join(root, "etc", "yum.repos.d", "*.repo"))
	sort.Strings(files)
	repos := []Repo{}
	for _, file := range files {
		f, err := os.Open(file) //nolint:gosec // configuração do sistema
		if err != nil {
			continue
		}
		ini := parseINI(f)
		_ = f.Close()
		ids := make([]string, 0, len(ini))
		for id := range ini {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			kv := ini[id]
			r := Repo{ID: id, Name: kv["name"], File: "/" + filepath.ToSlash(mustRel(root, file)), Enabled: true, Verified: defGPG}
			if b, ok := parseBool(kv["enabled"]); ok {
				r.Enabled = b
			}
			if b, ok := parseBool(kv["gpgcheck"]); ok {
				r.Verified = b
			}
			if r.Enabled && !r.Verified {
				r.Problem = RepoGPGCheckOff
			}
			repos = append(repos, r)
		}
	}
	return repos
}

func mustRel(root, p string) string {
	if r, err := filepath.Rel(root, p); err == nil {
		return r
	}
	return p
}

// --- Fontes APT ---

// AptSource é uma linha de fonte (formato de uma linha ou deb822).
type AptSource struct {
	URI           string
	Suite         string
	File          string
	Enabled       bool
	Trusted       bool
	AllowInsecure bool
}

// ParseAptSourcesList lê o formato de uma linha: "deb [opções] uri suíte componentes".
func ParseAptSourcesList(r io.Reader, file string) []AptSource {
	var out []AptSource
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if !strings.HasPrefix(l, "deb ") && !strings.HasPrefix(l, "deb\t") {
			continue
		}
		l = strings.TrimSpace(l[3:])
		s := AptSource{File: file, Enabled: true}
		if strings.HasPrefix(l, "[") {
			end := strings.IndexByte(l, ']')
			if end < 0 {
				continue
			}
			for _, opt := range strings.Fields(l[1:end]) {
				k, val, _ := strings.Cut(opt, "=")
				b, _ := parseBool(val)
				switch strings.ToLower(k) {
				case "trusted":
					s.Trusted = b
				case "allow-insecure":
					s.AllowInsecure = b
				}
			}
			l = strings.TrimSpace(l[end+1:])
		}
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		s.URI, s.Suite = f[0], f[1]
		out = append(out, s)
	}
	return out
}

// ParseAptDeb822 lê o formato deb822 (.sources): estrofes com Types, URIs, Suites, Trusted, Allow-Insecure, Enabled.
func ParseAptDeb822(r io.Reader, file string) []AptSource {
	var out []AptSource
	kv := map[string]string{}
	flush := func() {
		defer func() { kv = map[string]string{} }()
		if !strings.Contains(" "+kv["types"]+" ", " deb ") {
			return
		}
		enabled := true
		if b, ok := parseBool(kv["enabled"]); ok {
			enabled = b
		}
		trusted, _ := parseBool(kv["trusted"])
		insecure, _ := parseBool(kv["allow-insecure"])
		for _, uri := range strings.Fields(kv["uris"]) {
			for _, suite := range strings.Fields(kv["suites"]) {
				out = append(out, AptSource{URI: uri, Suite: suite, File: file, Enabled: enabled, Trusted: trusted, AllowInsecure: insecure})
			}
		}
	}
	last := ""
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		raw := sc.Text()
		l := strings.TrimSpace(raw)
		switch {
		case l == "":
			flush()
		case l[0] == '#':
		case raw[0] == ' ' || raw[0] == '\t':
			if last != "" && last != "signed-by" {
				kv[last] += " " + l
			}
		default:
			k, val, ok := strings.Cut(l, ":")
			if ok {
				last = strings.ToLower(strings.TrimSpace(k))
				kv[last] = strings.TrimSpace(val)
			}
		}
	}
	flush()
	return out
}

// listPrefix converte a URI e a suíte no prefixo dos arquivos em /var/lib/apt/lists
// ("http://deb.debian.org/debian" + "bookworm" → "deb.debian.org_debian_dists_bookworm").
func listPrefix(uri, suite string) string {
	u := uri
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if at := strings.LastIndexByte(strings.SplitN(u, "/", 2)[0], '@'); at >= 0 {
		u = u[at+1:] // credenciais na URI nunca entram no relatório nem no nome do arquivo
	}
	u = strings.TrimSuffix(u, "/")
	if strings.HasSuffix(suite, "/") {
		return strings.ReplaceAll(u+"/"+strings.TrimSuffix(suite, "/"), "/", "_")
	}
	return strings.ReplaceAll(u+"/dists/"+suite, "/", "_")
}

// redactURI tira usuário e senha da URI antes de mostrar.
func redactURI(uri string) string {
	i := strings.Index(uri, "://")
	if i < 0 {
		return uri
	}
	rest := uri[i+3:]
	host, path, _ := strings.Cut(rest, "/")
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	out := uri[:i+3] + host
	if path != "" {
		out += "/" + path
	}
	return out
}

// AptRepos lê as fontes, confere se cada lista baixada tem assinatura (InRelease ou Release.gpg) e procura no
// apt.conf opções que liberam pacotes sem autenticação.
func AptRepos(root string) []Repo {
	var sources []AptSource
	read := func(path string, deb822 bool) {
		f, err := os.Open(path) //nolint:gosec // configuração do sistema
		if err != nil {
			return
		}
		defer func() { _ = f.Close() }()
		rel := "/" + filepath.ToSlash(mustRel(root, path))
		if deb822 {
			sources = append(sources, ParseAptDeb822(f, rel)...)
		} else {
			sources = append(sources, ParseAptSourcesList(f, rel)...)
		}
	}
	read(filepath.Join(root, "etc", "apt", "sources.list"), false)
	lists, _ := filepath.Glob(filepath.Join(root, "etc", "apt", "sources.list.d", "*.list"))
	deb822, _ := filepath.Glob(filepath.Join(root, "etc", "apt", "sources.list.d", "*.sources"))
	sort.Strings(lists)
	sort.Strings(deb822)
	for _, p := range lists {
		read(p, false)
	}
	for _, p := range deb822 {
		read(p, true)
	}
	listDir := filepath.Join(root, "var", "lib", "apt", "lists")
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(listDir, name))
		return err == nil
	}
	repos := []Repo{}
	seen := map[string]bool{}
	for _, s := range sources {
		id := redactURI(s.URI) + " " + s.Suite
		if seen[id] {
			continue
		}
		seen[id] = true
		r := Repo{ID: id, File: s.File, Enabled: s.Enabled, Verified: !s.Trusted && !s.AllowInsecure}
		prefix := listPrefix(s.URI, s.Suite)
		switch {
		case !s.Enabled:
		case s.Trusted:
			r.Problem = RepoTrusted
		case s.AllowInsecure:
			r.Problem = RepoAllowInsecure
		case exists(prefix+"_Release") && !exists(prefix+"_InRelease") && !exists(prefix+"_Release.gpg"):
			r.Problem, r.Verified = RepoUnsignedList, false
		}
		repos = append(repos, r)
	}
	if opt := aptConfInsecure(root); opt != "" {
		repos = append(repos, Repo{ID: opt, File: "/etc/apt/apt.conf.d", Enabled: true, Problem: RepoAptConfInsecure})
	}
	return repos
}

var aptInsecureOption = regexp.MustCompile(`(?i)(AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecureRepositories)\s*"?(true|yes|1)"?`)

// aptConfInsecure devolve a primeira opção do apt.conf que libera pacote ou repositório sem assinatura.
func aptConfInsecure(root string) string {
	files, _ := filepath.Glob(filepath.Join(root, "etc", "apt", "apt.conf.d", "*"))
	files = append([]string{filepath.Join(root, "etc", "apt", "apt.conf")}, files...)
	for _, p := range files {
		b, err := os.ReadFile(p) //nolint:gosec // configuração do sistema
		if err != nil || len(b) > 1<<20 {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "//") || strings.HasPrefix(l, "#") {
				continue
			}
			if m := aptInsecureOption.FindStringSubmatch(l); m != nil {
				return m[1] + " em /" + filepath.ToSlash(mustRel(root, p))
			}
		}
	}
	return ""
}
