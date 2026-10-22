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
)

// LocalConfig é a configuração do executor que só o root altera (/etc/vigiahost/executor.json). O que está aqui
// não pode ser mudado pela API do core.
type LocalConfig struct {
	// AllowNoReserve libera pedidos acima da reserva do sistema (todos os núcleos, mais de 75% da RAM).
	AllowNoReserve bool `json:"allow_no_reserve"`
	// DeniedRoots soma-se aos caminhos que nunca são varridos (pseudo-sistemas).
	DeniedRoots []string `json:"denied_roots,omitempty"`
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
	case report.KindProcesses:
		if len(req.Paths) != 0 {
			return bad(ipc.CodeBadRequest, "inspeção de processos não recebe caminhos")
		}
	default:
		return bad(ipc.CodeBadRequest, "tipo de execução desconhecido")
	}
	if len(req.Exclude) > 256 {
		return bad(ipc.CodeBadRequest, "exclusões demais (máximo 256)")
	}
	denied := append(append([]string{}, deniedRoots...), extraDenied...)
	for _, p := range req.Paths {
		if err := checkPath(p); err != nil {
			return bad(ipc.CodePathRefused, "caminho %q recusado: %v", p, err)
		}
		allowed := slices.ContainsFunc(allowedUnderDenied, func(a string) bool { return under(p, a) })
		for _, d := range denied {
			if under(p, d) && !(allowed && slices.Contains(deniedRoots, d)) {
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
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "loop") || strings.HasPrefix(e.Name(), "ram") || strings.HasPrefix(e.Name(), "zram") {
				continue
			}
			if b, err := os.ReadFile(filepath.Join("/sys/block", e.Name(), "queue", "rotational")); err == nil && strings.TrimSpace(string(b)) == "1" {
				hw.Rotational = true
			}
		}
	}
	return hw
}

// UnitName é o nome determinístico da unidade de uma execução (ADR-004).
func UnitName(runID string) string { return "vigiahost-run-" + runID + ".service" }
