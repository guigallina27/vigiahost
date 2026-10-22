// Package updates é a execução "updates": correções de segurança pendentes (dnf updateinfo / APT), serviços e
// processos que ainda usam bibliotecas substituídas (dnf needs-restarting, needrestart ou leitura própria de
// /proc/PID/maps) e reinício pendente do kernel (escopo, seção 7.5, prioridades 1 e 2).
//
// Somente leitura e sem rede: usa o cache que o gerenciador de pacotes já tem e informa a idade dele. Só atualiza a
// lista de pacotes quando a configuração local do executor (root) permitir.
package updates

import (
	"bufio"
	"bytes"
	"sort"
	"strconv"
	"strings"
)

// Gravidade das correções, normalizada (o dnf usa Critical, Important, Moderate e Low; o APT não informa).
const (
	SevCritical  = "critical"
	SevImportant = "important"
	SevModerate  = "moderate"
	SevLow       = "low"
	SevUnknown   = "unknown"
)

var sevRank = map[string]int{SevCritical: 0, SevImportant: 1, SevModerate: 2, SevLow: 3, SevUnknown: 4}

func normSeverity(s string) string {
	switch strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(s, "/Sec."), "/sec.")) {
	case "critical":
		return SevCritical
	case "important":
		return SevImportant
	case "moderate":
		return SevModerate
	case "low":
		return SevLow
	}
	return SevUnknown
}

// worse devolve a mais grave das duas.
func worse(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if sevRank[b] < sevRank[a] {
		return b
	}
	return a
}

// Update é um pacote com versão nova disponível.
type Update struct {
	Name       string   `json:"name"`
	Arch       string   `json:"arch,omitempty"`
	Installed  string   `json:"installed,omitempty"`
	Available  string   `json:"available"`
	Repo       string   `json:"repo,omitempty"`
	Security   bool     `json:"security"`
	Severity   string   `json:"severity,omitempty"`
	Advisories []string `json:"advisories,omitempty"`
	CVEs       []string `json:"cves,omitempty"`
}

// Key identifica o pacote pela arquitetura.
func (u Update) Key() string { return u.Name + "." + u.Arch }

// SplitNEVRA separa "nome-[época:]versão-lançamento.arquitetura".
func SplitNEVRA(s string) (name, evr, arch string, ok bool) {
	dot := strings.LastIndexByte(s, '.')
	if dot <= 0 {
		return "", "", "", false
	}
	nevr, arch := s[:dot], s[dot+1:]
	r := strings.LastIndexByte(nevr, '-')
	if r <= 0 {
		return "", "", "", false
	}
	v := strings.LastIndexByte(nevr[:r], '-')
	if v <= 0 {
		return "", "", "", false
	}
	return nevr[:v], nevr[v+1:], arch, true
}

// Advisory é uma linha do "dnf updateinfo list --security".
type Advisory struct {
	ID       string
	Severity string
	Name     string
	EVR      string
	Arch     string
}

// ParseUpdateinfo lê "dnf updateinfo list --security" (e, com --with-cve, as linhas de CVE e referências).
func ParseUpdateinfo(out []byte) []Advisory {
	var list []Advisory
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 {
			continue
		}
		name, evr, arch, ok := SplitNEVRA(f[2])
		if !ok || !strings.Contains(f[0], "-") {
			continue
		}
		sev := SevUnknown
		if strings.HasSuffix(strings.ToLower(f[1]), "/sec.") {
			sev = normSeverity(f[1])
		} else if !strings.EqualFold(f[1], "security") {
			continue // bugfix, enhancement: não é correção de segurança
		}
		list = append(list, Advisory{ID: f[0], Severity: sev, Name: name, EVR: evr, Arch: arch})
	}
	return list
}

// ParseCheckUpdate lê "dnf check-update" (nome.arquitetura, versão, repositório). Nomes longos podem quebrar a
// linha; a seção "Obsoleting Packages" fica de fora.
func ParseCheckUpdate(out []byte) []Update {
	var list []Update
	sc := bufio.NewScanner(bytes.NewReader(out))
	carry := ""
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(l, "Obsoleting Packages") {
			break
		}
		if l == "" || strings.HasPrefix(l, "Last metadata") || strings.HasPrefix(l, "Security:") {
			continue
		}
		f := strings.Fields(l)
		if carry != "" {
			f = append([]string{carry}, f...)
			carry = ""
		}
		if len(f) == 1 {
			carry = f[0]
			continue
		}
		if len(f) != 3 {
			continue
		}
		dot := strings.LastIndexByte(f[0], '.')
		if dot <= 0 {
			continue
		}
		list = append(list, Update{Name: f[0][:dot], Arch: f[0][dot+1:], Available: f[1], Repo: f[2]})
	}
	return list
}

// MergeRPM junta check-update, avisos de segurança e versões instaladas. Um pacote é de segurança quando algum
// aviso de segurança cobre uma versão disponível.
func MergeRPM(updates []Update, advisories, cves []Advisory, installed map[string]string) (security, other []Update) {
	adv := map[string][]Advisory{}
	for _, a := range advisories {
		adv[a.Name+"."+a.Arch] = append(adv[a.Name+"."+a.Arch], a)
	}
	cveBy := map[string][]string{}
	for _, c := range cves {
		if strings.HasPrefix(c.ID, "CVE-") {
			cveBy[c.Name+"."+c.Arch] = append(cveBy[c.Name+"."+c.Arch], c.ID)
		}
	}
	seen := map[string]bool{}
	for _, u := range updates {
		seen[u.Key()] = true
	}
	// Aviso de pacote que o check-update não listou (outra arquitetura, versão excluída): entra mesmo assim.
	for key, list := range adv {
		if !seen[key] {
			last := list[len(list)-1]
			updates = append(updates, Update{Name: last.Name, Arch: last.Arch, Available: last.EVR})
		}
	}
	for _, u := range updates {
		u.Installed = installed[u.Key()]
		for _, a := range adv[u.Key()] {
			u.Security = true
			u.Severity = worse(u.Severity, a.Severity)
			u.Advisories = appendUnique(u.Advisories, a.ID)
		}
		for _, c := range cveBy[u.Key()] {
			u.CVEs = appendUnique(u.CVEs, c)
		}
		sort.Strings(u.Advisories)
		sort.Strings(u.CVEs)
		if u.Security {
			security = append(security, u)
		} else {
			other = append(other, u)
		}
	}
	sortUpdates(security)
	sortUpdates(other)
	return security, other
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func sortUpdates(list []Update) {
	sort.SliceStable(list, func(i, j int) bool {
		if sevRank[list[i].Severity] != sevRank[list[j].Severity] {
			return sevRank[list[i].Severity] < sevRank[list[j].Severity]
		}
		return list[i].Key() < list[j].Key()
	})
}

// ParseRPMInstalled lê "rpm -qa --qf '%{NAME}\t%{ARCH}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n'".
func ParseRPMInstalled(out []byte) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Split(strings.TrimSpace(l), "\t")
		if len(f) != 5 {
			continue
		}
		v := f[3] + "-" + f[4]
		if f[2] != "0" && f[2] != "" && f[2] != "(none)" {
			v = f[2] + ":" + v
		}
		m[f[0]+"."+f[1]] = v
	}
	return m
}

// ParseAptSimulate lê "apt-get -s dist-upgrade": "Inst nome [instalada] (nova origens [arquitetura])". É de segurança
// quando alguma origem é a suíte de segurança (bookworm-security, noble-security, Debian-Security).
func ParseAptSimulate(out []byte) (security, other []Update) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		rest, ok := strings.CutPrefix(l, "Inst ")
		if !ok {
			continue
		}
		name, rest, _ := strings.Cut(rest, " ")
		u := Update{Name: name}
		if strings.HasPrefix(rest, "[") {
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				continue
			}
			u.Installed, rest = rest[1:end], strings.TrimSpace(rest[end+1:])
		}
		if !strings.HasPrefix(rest, "(") || !strings.HasSuffix(rest, ")") {
			continue
		}
		inner := rest[1 : len(rest)-1]
		if i := strings.LastIndex(inner, " ["); i >= 0 && strings.HasSuffix(inner, "]") {
			u.Arch, inner = inner[i+2:len(inner)-1], inner[:i]
		}
		ver, origins, _ := strings.Cut(inner, " ")
		u.Available, u.Repo = ver, strings.TrimSpace(origins)
		for _, o := range strings.Split(u.Repo, ",") {
			o = strings.ToLower(strings.TrimSpace(o))
			if strings.Contains(o, "-security") || strings.HasPrefix(o, "debian-security") || strings.Contains(o, "/security") {
				u.Security = true
			}
		}
		if u.Security {
			u.Severity = SevUnknown
			security = append(security, u)
		} else {
			other = append(other, u)
		}
	}
	sortUpdates(security)
	sortUpdates(other)
	return security, other
}

// NeedsRestartingReboot interpreta "dnf needs-restarting -r": código 1 = reinício necessário, com os pacotes
// centrais atualizados desde o boot listados como "  * pacote".
func NeedsRestartingReboot(out []byte, code int) (required bool, pkgs []string) {
	for _, l := range strings.Split(string(out), "\n") {
		if p, ok := strings.CutPrefix(strings.TrimSpace(l), "* "); ok && p != "" {
			pkgs = append(pkgs, strings.TrimSpace(p))
		}
	}
	required = code == 1 || strings.Contains(string(out), "Reboot is required")
	return required, pkgs
}

// ParseUnitList lê uma unidade por linha ("dnf needs-restarting -s").
func ParseUnitList(out []byte) []string {
	var units []string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.ContainsAny(l, " \t:") && strings.Contains(l, ".") {
			units = appendUnique(units, l)
		}
	}
	sort.Strings(units)
	return units
}

// NeedRestart é a saída em lote do needrestart ("needrestart -b").
type NeedRestart struct {
	Version       string
	KernelCurrent string
	KernelLatest  string
	// KernelStatus: 0 desconhecido, 1 em dia, 2 atualização compatível pendente, 3 versão nova pendente.
	KernelStatus int
	Services     []string
}

// ParseNeedrestart lê as linhas "NEEDRESTART-CHAVE: valor".
func ParseNeedrestart(out []byte) NeedRestart {
	var n NeedRestart
	for _, l := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "NEEDRESTART-VER":
			n.Version = v
		case "NEEDRESTART-KCUR":
			n.KernelCurrent = v
		case "NEEDRESTART-KEXP":
			n.KernelLatest = v
		case "NEEDRESTART-KSTA":
			n.KernelStatus, _ = strconv.Atoi(v)
		case "NEEDRESTART-SVC":
			if v != "" {
				n.Services = appendUnique(n.Services, v)
			}
		}
	}
	sort.Strings(n.Services)
	return n
}

// DeletedMappings lê /proc/PID/maps e devolve os arquivos do sistema mapeados que foram apagados ou substituídos
// (biblioteca ou executável trocado por atualização). Memória anônima, memfd, /dev/shm e temporários ficam de fora:
// não são biblioteca de pacote.
func DeletedMappings(maps []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(maps))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 7 || f[len(f)-1] != "(deleted)" {
			continue
		}
		p := strings.Join(f[5:len(f)-1], " ")
		if !systemPath(p) {
			continue
		}
		out = appendUnique(out, p)
	}
	sort.Strings(out)
	return out
}

var systemPrefixes = []string{"/usr/", "/lib/", "/lib64/", "/lib32/", "/bin/", "/sbin/", "/opt/"}

func systemPath(p string) bool {
	if strings.HasPrefix(p, "/usr/lib/locale/") || strings.HasPrefix(p, "/usr/share/") {
		return false
	}
	for _, s := range systemPrefixes {
		if strings.HasPrefix(p, s) {
			return true
		}
	}
	return false
}

// UnitFromCgroup extrai a unidade systemd de /proc/PID/cgroup ("0::/system.slice/nginx.service").
func UnitFromCgroup(b []byte) string {
	path := ""
	for _, l := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(strings.TrimSpace(l), ":", 3)
		if len(parts) == 3 && (parts[0] == "0" || path == "") {
			path = parts[2]
		}
	}
	segs := strings.Split(path, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if strings.HasSuffix(segs[i], ".service") {
			return segs[i]
		}
	}
	return ""
}

// CompareKernel compara versões de kernel pelos números ("5.14.0-570.el9" < "5.14.0-611.el9").
func CompareKernel(a, b string) int {
	na, nb := numbers(a), numbers(b)
	for i := 0; i < len(na) && i < len(nb); i++ {
		if na[i] != nb[i] {
			if na[i] < nb[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(na) < len(nb):
		return -1
	case len(na) > len(nb):
		return 1
	}
	return 0
}

func numbers(s string) []int {
	var out []int
	cur, in := 0, false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			cur, in = cur*10+int(r-'0'), true
			continue
		}
		if in {
			out = append(out, cur)
			cur, in = 0, false
		}
	}
	if in {
		out = append(out, cur)
	}
	return out
}
