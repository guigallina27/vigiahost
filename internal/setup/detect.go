// Package setup implementa "vigiahost setup plan/apply/uninstall" (escopo, seção 15; ADR-015): detecta o ambiente,
// mostra as alterações previstas, aplica de forma idempotente registrando cada alteração em um manifesto com backup e
// desfaz o que foi registrado na desinstalação.
package setup

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/guigallina27/vigiahost/internal/engines/clamav"
	"github.com/guigallina27/vigiahost/internal/scan"
	"github.com/guigallina27/vigiahost/internal/sysinfo"
)

// Serviços do produto, na ordem de partida.
var Units = []string{"vigiahost-executor.service", "vigiahost-core.service"}

// System isola o que o setup toca no servidor, para os testes trocarem a raiz e o systemctl.
type System struct {
	Root      string // prefixo dos caminhos ("" = raiz real)
	Systemctl func(ctx context.Context, args ...string) (string, error)
	// Engines descobre os motores; nil usa a descoberta real (sem compilar regras nem esperar o clamd).
	Engines func(ctx context.Context) scan.EngineInfo
	Now     func() time.Time
}

// Host devolve o System da máquina real.
func Host() *System {
	return &System{
		Systemctl: func(ctx context.Context, args ...string) (string, error) {
			out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput() //nolint:gosec // argumentos fixos do setup
			return strings.TrimSpace(string(out)), err
		},
		Now: time.Now,
	}
}

func (s *System) path(p string) string {
	if s.Root == "" {
		return p
	}
	return filepath.Join(s.Root, filepath.FromSlash(p))
}

func (s *System) exists(p string) bool {
	_, err := os.Lstat(s.path(p))
	return err == nil
}

// ServiceState é o estado de uma unidade antes de qualquer alteração.
type ServiceState struct {
	Enabled string `json:"enabled"` // enabled, disabled, static, masked, not-found
	Active  string `json:"active"`  // active, inactive, failed...
}

// Environment é o que o plano detectou.
type Environment struct {
	Root       bool                    `json:"root"`
	Distro     string                  `json:"distro"`
	Family     string                  `json:"family"`
	Arch       string                  `json:"arch"`
	Systemd    bool                    `json:"systemd"`
	CgroupV2   bool                    `json:"cgroup_v2"`
	PSI        bool                    `json:"psi"`
	Panels     []string                `json:"panels,omitempty"`
	OtherAV    []string                `json:"other_av,omitempty"`
	SELinux    string                  `json:"selinux,omitempty"` // enforcing, permissive
	AppArmor   bool                    `json:"apparmor"`
	Firewalls  []string                `json:"firewalls,omitempty"`
	Engines    scan.EngineInfo         `json:"engines"`
	Services   map[string]ServiceState `json:"services"`
	ListenBusy string                  `json:"listen_busy,omitempty"` // erro ao reservar a porta pedida
}

// Indícios de painéis de hospedagem (só informativo na 1A; adaptadores entram na Fase 3).
var panels = []struct{ name, path string }{
	{"cPanel/WHM", "/usr/local/cpanel/cpanel"},
	{"Plesk", "/usr/local/psa/version"},
	{"DirectAdmin", "/usr/local/directadmin/directadmin"},
	{"Webuzo", "/usr/local/webuzo"},
	{"CWP", "/usr/local/cwpsrv"},
	{"CyberPanel", "/usr/local/CyberCP"},
	{"aaPanel", "/www/server/panel"},
	{"ISPConfig", "/usr/local/ispconfig"},
	{"Virtualmin", "/etc/webmin/virtual-server"},
	{"HestiaCP", "/usr/local/hestia"},
}

// Outros antivírus e agentes que também leem arquivos e processos: convivem, mas disputam disco e CPU.
var otherAV = []struct{ name, path string }{
	{"Imunify360/ImunifyAV", "/usr/bin/imunify-antivirus"},
	{"Imunify360", "/usr/bin/imunify360-agent"},
	{"Linux Malware Detect (maldet)", "/usr/local/maldetect/maldet"},
	{"ESET", "/opt/eset"},
	{"Sophos", "/opt/sophos-spl"},
	{"CrowdStrike Falcon", "/opt/CrowdStrike"},
	{"Wazuh", "/var/ossec/bin/wazuh-control"},
	{"Microsoft Defender", "/opt/microsoft/mdatp"},
}

var firewalls = []struct{ name, path string }{
	{"csf", "/usr/sbin/csf"},
	{"firewalld", "/usr/bin/firewall-cmd"},
	{"ufw", "/usr/sbin/ufw"},
}

// Detect lê o ambiente sem alterar nada.
func (s *System) Detect(ctx context.Context, listen string) Environment {
	caps := sysinfo.Detect(os.DirFS(s.path("/")))
	env := Environment{
		Root: os.Geteuid() == 0, Distro: caps.DistroName, Family: caps.Family(), Arch: caps.Arch,
		Systemd: caps.Systemd, CgroupV2: caps.CgroupV2, PSI: caps.PSI, Services: map[string]ServiceState{},
	}
	if env.Distro == "" {
		env.Distro = caps.DistroID
	}
	for _, p := range panels {
		if s.exists(p.path) {
			env.Panels = append(env.Panels, p.name)
		}
	}
	for _, a := range otherAV {
		if s.exists(a.path) && !slices.Contains(env.OtherAV, a.name) {
			env.OtherAV = append(env.OtherAV, a.name)
		}
	}
	for _, f := range firewalls {
		if s.exists(f.path) {
			env.Firewalls = append(env.Firewalls, f.name)
		}
	}
	if b, err := os.ReadFile(s.path("/sys/fs/selinux/enforce")); err == nil { //nolint:gosec // caminho fixo
		env.SELinux = map[bool]string{true: "enforcing", false: "permissive"}[strings.TrimSpace(string(b)) == "1"]
	}
	env.AppArmor = s.exists("/sys/kernel/security/apparmor")
	if s.Engines != nil {
		env.Engines = s.Engines(ctx)
	} else {
		env.Engines = scan.DiscoverEngines(ctx, "", scan.DiscoverOptions{}, func() (clamav.Config, bool) {
			return clamav.Discover(os.DirFS(s.path("/")))
		})
	}
	for _, u := range Units {
		env.Services[u] = s.serviceState(ctx, u)
	}
	if listen != "" && env.Services["vigiahost-core.service"].Active != "active" {
		if l, err := net.Listen("tcp", listen); err != nil {
			env.ListenBusy = err.Error()
			if errors.Is(err, syscall.EADDRINUSE) {
				env.ListenBusy = "a porta já está em uso por outro programa"
			}
		} else {
			_ = l.Close()
		}
	}
	return env
}

func (s *System) serviceState(ctx context.Context, unit string) ServiceState {
	enabled, _ := s.Systemctl(ctx, "is-enabled", unit)
	active, _ := s.Systemctl(ctx, "is-active", unit)
	st := ServiceState{Enabled: firstWord(enabled), Active: firstWord(active)}
	if st.Enabled == "" || strings.Contains(enabled, "No such file") || strings.Contains(enabled, "not-found") {
		st.Enabled = "not-found"
	}
	return st
}

func firstWord(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

// fileEqual indica se o arquivo existe com exatamente este conteúdo.
func (s *System) fileEqual(p string, data []byte) bool {
	b, err := os.ReadFile(s.path(p)) //nolint:gosec // caminhos fixos do setup
	return err == nil && string(b) == string(data)
}
