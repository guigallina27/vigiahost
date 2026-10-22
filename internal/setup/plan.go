package setup

import (
	"fmt"
	"io"
	"net"
	"strings"
)

// Caminhos fixos do produto.
const (
	DefaultListen = "127.0.0.1:8743"
	CoreDropIn    = "/etc/systemd/system/vigiahost-core.service.d/10-setup.conf"
	ManifestPath  = "/etc/vigiahost/setup-manifest.json"
	BackupRoot    = "/var/backups/vigiahost"
	CoreBinary    = "/usr/bin/vigiahost"
)

// Dados de cada componente, apagados só no --purge.
var DataDirs = []string{"/var/lib/vigiahost", "/var/lib/vigiahost-executor", "/etc/vigiahost"}

// Options são as respostas do administrador (parâmetros ou arquivo de respostas).
type Options struct {
	Listen     string `json:"listen"`
	TLSCert    string `json:"tls_cert,omitempty"`
	TLSKey     string `json:"tls_key,omitempty"`
	TrustProxy bool   `json:"trust_proxy,omitempty"`
}

func (o Options) custom() bool {
	return (o.Listen != "" && o.Listen != DefaultListen) || o.TLSCert != "" || o.TLSKey != "" || o.TrustProxy
}

// Action é uma alteração prevista. Done indica que o sistema já está como deveria (reexecução sem efeito).
type Action struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Kind        string `json:"kind"` // file, remove-file, service, restart
	Path        string `json:"path,omitempty"`
	Unit        string `json:"unit,omitempty"`
	Content     []byte `json:"-"`
	Done        bool   `json:"done"`
}

// Plan é o resultado de "setup plan": ambiente, bloqueios, avisos, alterações e recomendações.
type Plan struct {
	Options         Options     `json:"options"`
	Env             Environment `json:"environment"`
	Blockers        []string    `json:"blockers,omitempty"`
	Warnings        []string    `json:"warnings,omitempty"`
	Actions         []Action    `json:"actions"`
	Recommendations []string    `json:"recommendations,omitempty"`
}

// Pending indica se ainda há alteração a fazer.
func (p Plan) Pending() bool {
	for _, a := range p.Actions {
		if !a.Done {
			return true
		}
	}
	return false
}

// coreDropIn monta o drop-in do systemd com as opções do serviço web.
func coreDropIn(o Options) []byte {
	args := []string{CoreBinary, "serve", "-listen", o.Listen}
	if o.TLSCert != "" {
		args = append(args, "-tls-cert", o.TLSCert, "-tls-key", o.TLSKey)
	}
	if o.TrustProxy {
		args = append(args, "-trust-proxy")
	}
	return []byte("# Gerado por \"vigiahost setup apply\". Para mudar, rode o setup de novo com outras opções.\n" +
		"[Service]\nExecStart=\nExecStart=" + strings.Join(args, " ") + "\n")
}

// MakePlan calcula as alterações a partir do ambiente detectado e do manifesto anterior (nil na primeira vez).
func (s *System) MakePlan(env Environment, o Options, prev *Manifest) Plan {
	if o.Listen == "" {
		o.Listen = DefaultListen
	}
	p := Plan{Options: o, Env: env}

	// Bloqueios: o apply recusa seguir.
	if !env.Systemd {
		p.Blockers = append(p.Blockers, "systemd não está em execução: o produto depende dele para isolar as execuções e aplicar limites")
	}
	for _, u := range Units {
		if env.Services[u].Enabled == "not-found" {
			p.Blockers = append(p.Blockers, "unidade "+u+" não encontrada: instale o pacote vigiahost antes do setup")
		}
		if env.Services[u].Enabled == "masked" {
			p.Blockers = append(p.Blockers, "unidade "+u+" está mascarada (systemctl unmask "+u+" para liberar)")
		}
	}
	host, port, err := net.SplitHostPort(o.Listen)
	switch {
	case err != nil || port == "":
		p.Blockers = append(p.Blockers, fmt.Sprintf("endereço de escuta inválido %q (use IP:porta, ex.: 127.0.0.1:8743)", o.Listen))
	case env.ListenBusy != "":
		p.Blockers = append(p.Blockers, "não foi possível reservar "+o.Listen+": "+env.ListenBusy)
	}
	if (o.TLSCert == "") != (o.TLSKey == "") {
		p.Blockers = append(p.Blockers, "informe -tls-cert e -tls-key juntos")
	}
	for _, f := range []string{o.TLSCert, o.TLSKey} {
		if f != "" && !s.exists(f) {
			p.Blockers = append(p.Blockers, "arquivo não encontrado: "+f)
		}
	}

	// Avisos.
	local := host == "127.0.0.1" || host == "::1" || host == "localhost"
	if !env.CgroupV2 {
		p.Warnings = append(p.Warnings, "sem cgroup v2: pausar execuções e limitar leitura de disco ficam indisponíveis")
	}
	if env.Engines.YR == "" {
		p.Warnings = append(p.Warnings, "YARA-X (yr) não encontrado: a varredura de arquivos fica sem as regras do produto")
	}
	if env.Engines.Clamd == nil && env.Engines.Clamscan == "" {
		p.Warnings = append(p.Warnings, "ClamAV não encontrado: a varredura fica sem as assinaturas do ClamAV")
	} else if env.Engines.Clamd == nil {
		p.Warnings = append(p.Warnings, "clamd não respondeu ("+env.Engines.ClamdError+"): o ClamAV vai rodar pelo clamscan, bem mais lento")
	}
	if len(env.OtherAV) > 0 {
		p.Warnings = append(p.Warnings, "outros antivírus/agentes detectados ("+strings.Join(env.OtherAV, ", ")+
			"): convivem, mas agende as verificações em horários diferentes para não disputar disco e CPU")
	}
	if env.SELinux == "enforcing" {
		p.Warnings = append(p.Warnings, "SELinux em modo enforcing: os serviços rodam no domínio padrão das unidades do systemd; a política própria chega na Fase 2")
	}
	if !local && o.TLSCert == "" && !o.TrustProxy {
		p.Warnings = append(p.Warnings, "o painel vai escutar fora do endereço local com certificado autoassinado: o navegador pede uma exceção, confira a impressão digital mostrada no fim")
	}

	// Alterações.
	if o.custom() {
		data := coreDropIn(o)
		p.Actions = append(p.Actions, Action{ID: "core-config", Kind: "file", Path: CoreDropIn, Content: data,
			Description: "gravar as opções do serviço web em " + CoreDropIn + " (escuta " + o.Listen + ")",
			Done:        s.fileEqual(CoreDropIn, data)})
	} else if s.exists(CoreDropIn) && prev.wrote(CoreDropIn) {
		p.Actions = append(p.Actions, Action{ID: "core-config", Kind: "remove-file", Path: CoreDropIn,
			Description: "remover as opções personalizadas do serviço web (volta à escuta padrão " + DefaultListen + ")"})
	}
	configChanged := len(p.Actions) > 0 && !p.Actions[0].Done
	for _, u := range Units {
		st := env.Services[u]
		ready := st.Enabled == "enabled" && st.Active == "active"
		p.Actions = append(p.Actions, Action{ID: "enable-" + strings.TrimSuffix(strings.TrimPrefix(u, "vigiahost-"), ".service"),
			Kind: "service", Unit: u, Done: ready,
			Description: "habilitar e iniciar " + u + " (hoje: " + st.Enabled + ", " + st.Active + ")"})
	}
	if configChanged && env.Services["vigiahost-core.service"].Active == "active" {
		p.Actions = append(p.Actions, Action{ID: "restart-core", Kind: "restart", Unit: "vigiahost-core.service",
			Description: "reiniciar vigiahost-core.service para valer a nova configuração"})
	}

	// Recomendações (nunca aplicadas automaticamente).
	if env.Engines.YR == "" {
		p.Recommendations = append(p.Recommendations,
			"instale o YARA-X: binário oficial \"yr\" dos releases de github.com/VirusTotal/yara-x em /usr/local/bin/yr")
	}
	if env.Engines.Clamd == nil && env.Engines.Clamscan == "" {
		switch env.Family {
		case "rhel":
			p.Recommendations = append(p.Recommendations, "instale o ClamAV (EPEL): dnf install clamav clamd clamav-update && systemctl enable --now clamd@scan")
		case "debian":
			p.Recommendations = append(p.Recommendations, "instale o ClamAV: apt install clamav clamav-daemon && systemctl enable --now clamav-daemon")
		default:
			p.Recommendations = append(p.Recommendations, "instale o ClamAV com o gerenciador de pacotes da distribuição e habilite o clamd")
		}
	}
	if !local && !o.TrustProxy {
		p.Recommendations = append(p.Recommendations, firewallHints(env.Firewalls, port)...)
	}
	if local {
		p.Recommendations = append(p.Recommendations,
			"acesse pelo túnel SSH: ssh -L "+port+":127.0.0.1:"+port+" root@servidor e abra http://127.0.0.1:"+port)
	}
	return p
}

// firewallHints mostra como liberar a porta; o setup nunca altera o firewall (escopo, seção 15).
func firewallHints(fw []string, port string) []string {
	if len(fw) == 0 {
		return []string{"libere a porta " + port + "/tcp no firewall só para os IPs de administração"}
	}
	var out []string
	for _, f := range fw {
		switch f {
		case "csf":
			out = append(out, "csf: acrescente "+port+" a TCP_IN em /etc/csf/csf.conf (ou só o IP de administração em csf.allow) e rode csf -r")
		case "firewalld":
			out = append(out, "firewalld: firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=SEU_IP port port="+port+
				" protocol=tcp accept' && firewall-cmd --reload")
		case "ufw":
			out = append(out, "ufw: ufw allow from SEU_IP to any port "+port+" proto tcp")
		}
	}
	return out
}

// Render escreve o plano para o terminal.
func (p Plan) Render(w io.Writer) {
	e := p.Env
	fmt.Fprintf(w, "Ambiente\n")
	fmt.Fprintf(w, "  Sistema      %s (%s, %s)\n", dash(e.Distro), dash(e.Family), dash(e.Arch))
	fmt.Fprintf(w, "  systemd      %s · cgroup v2 %s · PSI %s\n", yes(e.Systemd), yes(e.CgroupV2), yes(e.PSI))
	fmt.Fprintf(w, "  Painéis      %s\n", list(e.Panels))
	fmt.Fprintf(w, "  SELinux      %s · AppArmor %s\n", dash(e.SELinux), yes(e.AppArmor))
	fmt.Fprintf(w, "  Firewall     %s\n", list(e.Firewalls))
	yr := "não encontrado"
	if e.Engines.YR != "" {
		yr = e.Engines.YR + " " + e.Engines.YRVersion
	}
	clam := "não encontrado"
	switch {
	case e.Engines.Clamd != nil:
		clam = "clamd em " + e.Engines.Clamd.LocalSocket + " (" + e.Engines.ClamVersion.Engine + ")"
	case e.Engines.Clamscan != "":
		clam = "só clamscan (" + e.Engines.Clamscan + ")"
	}
	fmt.Fprintf(w, "  YARA-X       %s\n  ClamAV       %s\n", yr, clam)
	for _, u := range Units {
		st := e.Services[u]
		fmt.Fprintf(w, "  %-12s %s, %s\n", strings.TrimSuffix(u, ".service"), st.Enabled, st.Active)
	}
	section(w, "Impedimentos (resolva antes do apply)", p.Blockers)
	section(w, "Avisos", p.Warnings)
	fmt.Fprintf(w, "\nAlterações previstas\n")
	for i, a := range p.Actions {
		mark := " "
		if a.Done {
			mark = "✓"
		}
		fmt.Fprintf(w, "  %s %d. %s\n", mark, i+1, a.Description)
	}
	if !p.Pending() {
		fmt.Fprintf(w, "  nada a fazer: o sistema já está como o plano pede\n")
	}
	section(w, "Recomendações (não aplicadas automaticamente)", p.Recommendations)
}

func section(w io.Writer, title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s\n", title)
	for _, it := range items {
		fmt.Fprintf(w, "  - %s\n", it)
	}
}

func yes(b bool) string {
	if b {
		return "sim"
	}
	return "não"
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func list(s []string) string {
	if len(s) == 0 {
		return "nenhum"
	}
	return strings.Join(s, ", ")
}
