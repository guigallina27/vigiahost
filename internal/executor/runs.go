package executor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/profile"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/rules"
)

// LocalConfig é a configuração do executor que só o root altera (/etc/vigiahost/executor.json). O que está aqui
// não pode ser mudado pela API do core.
type LocalConfig struct {
	// AllowNoReserve libera pedidos acima da reserva do sistema (todos os núcleos, mais de 75% da RAM).
	AllowNoReserve bool `json:"allow_no_reserve"`
	// DeniedRoots soma-se aos caminhos que nunca são varridos (pseudo-sistemas).
	DeniedRoots []string `json:"denied_roots,omitempty"`
	// RefreshPackageMetadata deixa a execução "updates" atualizar a lista de pacotes (dnf makecache / apt-get update)
	// antes de conferir as correções. Desligado, ela usa só o cache existente, sem rede, e informa a idade dele.
	RefreshPackageMetadata bool `json:"refresh_package_metadata,omitempty"`
}

// LoadLocalConfig lê a configuração local; ausente vale o padrão (sem liberação).
func LoadLocalConfig(path string) (LocalConfig, error) {
	var c LocalConfig
	data, err := os.ReadFile(path) //nolint:gosec // caminho fixo da configuração do root
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return c, dec.Decode(&c)
}

var runIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// Raízes que nunca entram numa varredura de arquivos.
var deniedRoots = []string{"/proc", "/sys", "/dev", "/run/user"}

// allowedUnderDenied são exceções dentro das áreas recusadas: /dev/shm é tmpfs de arquivos comuns e lugar onde
// malware costuma ficar (escopo, seção 9.1).
var allowedUnderDenied = []string{"/dev/shm"}

func under(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }

// MaxPaths limita raízes por execução e contas por filtro de dono.
const MaxPaths = 10000

// ValidateRequest confere identificador, tipo e caminhos do pedido. O executor não confia no core.
func ValidateRequest(req *report.Request, extraDenied []string) error {
	bad := func(code, format string, args ...any) error {
		return &ipc.Error{Code: code, Message: fmt.Sprintf(format, args...)}
	}
	if !runIDPattern.MatchString(req.RunID) {
		return bad(ipc.CodeBadRequest, "identificador de execução inválido")
	}
	switch req.Kind {
	case report.KindFiles:
		// Até 64 caminhos escolhidos à mão; a verificação de várias contas manda um diretório pessoal por conta.
		if len(req.Paths) == 0 || len(req.Paths) > MaxPaths {
			return bad(ipc.CodeBadRequest, "informe de 1 a %d caminhos", MaxPaths)
		}
		for root, uids := range req.Owners {
			if !slices.Contains(req.Paths, root) {
				return bad(ipc.CodeBadRequest, "filtro de dono para %q, que não é raiz da execução", root)
			}
			if len(uids) == 0 || len(uids) > MaxPaths {
				return bad(ipc.CodeBadRequest, "filtro de dono de %q com %d contas", root, len(uids))
			}
		}
	case report.KindProcesses, report.KindIntegrity, report.KindUpdates:
		// Verificações do sistema inteiro: o escopo é fixo e nenhum caminho vem do core.
		if len(req.Paths) != 0 || len(req.Owners) != 0 {
			return bad(ipc.CodeBadRequest, "execução do tipo %s não recebe caminhos", req.Kind)
		}
	default:
		return bad(ipc.CodeBadRequest, "tipo de execução desconhecido")
	}
	if len(req.Exclude) > 256 {
		return bad(ipc.CodeBadRequest, "exclusões demais (máximo 256)")
	}
	if err := rules.ValidDisabled(req.DisabledRuleSources); err != nil {
		return bad(ipc.CodeBadRequest, "%v", err)
	}
	denied := append(append([]string{}, deniedRoots...), extraDenied...)
	for _, p := range req.Paths {
		if err := checkPath(p); err != nil {
			return bad(ipc.CodePathRefused, "caminho %q recusado: %v", p, err)
		}
		allowed := slices.ContainsFunc(allowedUnderDenied, func(a string) bool { return under(p, a) })
		for _, d := range denied {
			if under(p, d) && (!allowed || !slices.Contains(deniedRoots, d)) {
				return bad(ipc.CodePathRefused, "caminho %q recusado: área que não é varrida", p)
			}
		}
		info, err := os.Stat(p)
		if err != nil || !info.IsDir() {
			return bad(ipc.CodePathRefused, "caminho %q não é um diretório existente", p)
		}
	}
	for _, p := range req.Exclude {
		if err := checkPath(p); err != nil {
			return bad(ipc.CodePathRefused, "exclusão %q recusada: %v", p, err)
		}
	}
	return nil
}

func checkPath(p string) error {
	switch {
	case p == "" || !filepath.IsAbs(p):
		return errors.New("precisa ser absoluto")
	case strings.ContainsRune(p, 0) || strings.ContainsAny(p, "\n\r"):
		return errors.New("caracteres inválidos")
	case filepath.Clean(p) != p:
		return errors.New("precisa estar normalizado (sem .., // ou / no fim)")
	case len(p) > 4096:
		return errors.New("longo demais")
	}
	return nil
}

// DetectHardware lê núcleos, memória e se o disco do sistema é rotacional.
func DetectHardware() profile.Hardware {
	hw := profile.Hardware{CPUs: runtime.NumCPU()}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
				kb, _ := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "kB")), 10, 64)
				hw.MemoryBytes = kb << 10
			}
		}
		_ = f.Close()
	}
	if entries, err := os.ReadDir("/sys/block"); err == nil {
		var names []string
		rotational := map[string]bool{}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "loop") || strings.HasPrefix(e.Name(), "ram") || strings.HasPrefix(e.Name(), "zram") ||
				strings.HasPrefix(e.Name(), "dm-") || strings.HasPrefix(e.Name(), "md") || strings.HasPrefix(e.Name(), "sr") {
				continue
			}
			names = append(names, e.Name())
			if b, err := os.ReadFile(filepath.Join("/sys/block", e.Name(), "queue", "rotational")); err == nil && strings.TrimSpace(string(b)) == "1" {
				hw.Rotational = true
				rotational[e.Name()] = true
			}
		}
		hw.DiskType = DiskType(names, rotational)
	}
	return hw
}

// DiskType classifica os discos pelo mais lento: hdd se algum é rotacional, nvme se todos são NVMe, ssd no resto.
// Sem disco identificado, devolve vazio (o perfil cai no campo Rotational).
func DiskType(names []string, rotational map[string]bool) string {
	if len(names) == 0 {
		return ""
	}
	nvme := true
	for _, n := range names {
		if rotational[n] {
			return profile.DiskHDD
		}
		if !strings.HasPrefix(n, "nvme") {
			nvme = false
		}
	}
	if nvme {
		return profile.DiskNVMe
	}
	return profile.DiskSSD
}

// Capacidades usadas pelas unidades das execuções (bits de linux/capability.h).
const (
	capChown          = 1 << 0
	capDACOverride    = 1 << 1
	capDACReadSearch  = 1 << 2
	capFOwner         = 1 << 3
	capSetGID         = 1 << 6
	capSetUID         = 1 << 7
	capNetBindService = 1 << 10
	capSysPtrace      = 1 << 19
)

// Capacidades do processo da execução: ler qualquer arquivo (DAC_READ_SEARCH) e conectar ao socket do clamd de
// outro dono (DAC_OVERRIDE). Com ProtectSystem=strict a escrita continua restrita aos ReadWritePaths.
const runCapabilities = capDACOverride | capDACReadSearch

// UnitSpec é o processo e o isolamento da unidade transitória de cada tipo de execução (ADR-022).
type UnitSpec struct {
	Sub      string   // subcomando do executor
	Args     []string // argumentos extras do subcomando (fixos, nunca vindos do core)
	Families []string // RestrictAddressFamilies
	Caps     uint64   // CapabilityBoundingSet
	// PrivateNetwork isola a rede; sem ele, IPAddressDeny=any bloqueia todo tráfego IP mesmo na rede do sistema.
	PrivateNetwork bool
	IPDenyAll      bool
	// Write são os diretórios do sistema que a execução pode alterar, além dos dela (só os que existem).
	Write []string
}

// SpecFor monta a unidade de um tipo já validado. exists diz se um diretório existe no sistema.
func SpecFor(kind report.Kind, local LocalConfig, exists func(string) bool) UnitSpec {
	s := UnitSpec{Sub: "scan", Families: []string{"AF_UNIX"}, Caps: runCapabilities, PrivateNetwork: true}
	switch kind {
	case report.KindProcesses:
		// O inspetor lê /proc de todos os processos (SYS_PTRACE para /proc/PID/exe de outros usuários) e a rede por
		// netlink (sock_diag). A busca por portas ocultas compara a tabela do kernel com bind() nas portas não
		// listadas, por isso roda na rede do sistema: IPAddressDeny=any impede qualquer tráfego IP e
		// NET_BIND_SERVICE só serve para testar portas abaixo de 1024 (o socket é fechado na hora, sem listen).
		s.Sub = "inspect"
		s.Families = []string{"AF_UNIX", "AF_NETLINK", "AF_INET", "AF_INET6"}
		s.Caps = runCapabilities | capSysPtrace | capNetBindService
		s.PrivateNetwork, s.IPDenyAll = false, true
	case report.KindIntegrity:
		// rpm -Va / dpkg --verify leem todos os arquivos dos pacotes; nada é gravado fora da execução.
		s.Sub = "integrity"
	case report.KindUpdates:
		// O dnf grava a trava e o cache de metadados em /var/cache/dnf mesmo no modo só cache (-C). /proc/PID/maps de
		// outros usuários (bibliotecas apagadas em uso) exige SYS_PTRACE.
		s.Sub = "updates"
		s.Caps = runCapabilities | capSysPtrace
		s.Write = []string{"/var/cache/dnf"}
		if local.RefreshPackageMetadata {
			// Atualizar a lista de pacotes é a única execução com rede: só os espelhos configurados no sistema. O apt
			// baixa como _apt (troca de usuário e dono dos arquivos parciais).
			s.Args = []string{"-refresh"}
			s.PrivateNetwork = false
			s.Families = []string{"AF_UNIX", "AF_NETLINK", "AF_INET", "AF_INET6"}
			s.Caps |= capChown | capFOwner | capSetUID | capSetGID
			s.Write = append(s.Write, "/var/lib/dnf", "/var/lib/apt/lists", "/var/cache/apt")
		}
	}
	w := s.Write[:0]
	for _, d := range s.Write {
		if exists(d) {
			w = append(w, d)
		}
	}
	s.Write = w
	return s
}

// UnitName é o nome determinístico da unidade de uma execução (ADR-004).
func UnitName(runID string) string { return "vigiahost-run-" + runID + ".service" }

// strictDecode recusa campos desconhecidos: o core e o executor vêm do mesmo pacote.
func strictDecode(body json.RawMessage, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &ipc.Error{Code: ipc.CodeBadRequest, Message: "corpo inválido: " + err.Error()}
	}
	return nil
}
