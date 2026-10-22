package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"

	"github.com/guigallina27/vigiahost/internal/accounts"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/profile"
	"github.com/guigallina27/vigiahost/internal/report"
)

// Capacidades do processo da execução: ler qualquer arquivo (DAC_READ_SEARCH) e conectar ao socket do clamd de
// outro dono (DAC_OVERRIDE). Com ProtectSystem=strict a escrita continua restrita aos ReadWritePaths.
const runCapabilities = 1<<1 | 1<<2 // CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH

// Runs cria e acompanha execuções em unidades transitórias do systemd.
type Runs struct {
	Logger   *slog.Logger
	StateDir string // /var/lib/vigiahost-executor
	Exe      string // binário do executor (o processo da execução é "vigiahost-executor scan")
	CoreGID  int    // grupo do core, que lê o diretório da execução
	Local    LocalConfig
	Hardware profile.Hardware
	// UserRules é o diretório das fontes locais de regras (padrão rules.UserDir).
	UserRules string

	mu   sync.Mutex
	conn *sddbus.Conn
}

func (r *Runs) runsDir() string         { return filepath.Join(r.StateDir, "runs") }
func (r *Runs) runDir(id string) string { return filepath.Join(r.runsDir(), id) }

// Prepare cria a estrutura de diretórios: runs/ legível pelo grupo do core; cache e regras só do root. Sem setgid:
// a unidade do executor tem RestrictSUIDSGID, e o grupo dos arquivos de cada execução vem do Group= da unidade.
func (r *Runs) Prepare() error {
	for _, d := range []struct {
		path  string
		mode  os.FileMode
		group bool
	}{
		{r.StateDir, 0o750, true},
		{r.runsDir(), 0o750, true},
		{filepath.Join(r.StateDir, "cache"), 0o700, false},
		{filepath.Join(r.StateDir, "rules"), 0o700, false},
	} {
		if err := os.MkdirAll(d.path, d.mode.Perm()); err != nil {
			return err
		}
		if d.group && r.CoreGID >= 0 {
			if err := os.Chown(d.path, 0, r.CoreGID); err != nil {
				return err
			}
		}
		if err := os.Chmod(d.path, d.mode); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runs) dbus(ctx context.Context) (*sddbus.Conn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil && r.conn.Connected() {
		return r.conn, nil
	}
	c, err := sddbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("D-Bus do systemd: %w", err)
	}
	r.conn = c
	return c, nil
}

// Close encerra a conexão com o D-Bus.
func (r *Runs) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		r.conn.Close()
		r.conn = nil
	}
}

func prop(name string, v any) sddbus.Property {
	return sddbus.Property{Name: name, Value: dbus.MakeVariant(v)}
}

// limitProps converte o perfil em propriedades de cgroup.
func limitProps(p report.Profile) []sddbus.Property {
	props := []sddbus.Property{prop("IOWeight", uint64(max(p.IOWeight, 1)))} //nolint:gosec // validado por Enforce
	if p.CPUQuotaPercent > 0 {
		props = append(props, prop("CPUQuotaPerSecUSec", uint64(p.CPUQuotaPercent)*10_000)) //nolint:gosec // validado por Enforce
	}
	if p.MemoryMaxBytes > 0 {
		props = append(props,
			prop("MemoryMax", uint64(p.MemoryMaxBytes)),      //nolint:gosec // validado por Enforce
			prop("MemoryHigh", uint64(p.MemoryMaxBytes)*3/4)) //nolint:gosec // contém o cache de páginas antes do teto
	}
	return props
}

// Start valida, aplica as travas e cria a unidade transitória da execução.
func (r *Runs) Start(ctx context.Context, body json.RawMessage) (any, error) {
	var in ipc.RunStart
	if err := strictDecode(body, &in); err != nil {
		return nil, err
	}
	if err := ValidateRequest(&in.Request, r.Local.DeniedRoots); err != nil {
		return nil, err
	}
	p, err := profile.Enforce(in.Request.Profile, r.Hardware, in.NoReserve, r.Local.AllowNoReserve)
	if err != nil {
		return nil, &ipc.Error{Code: ipc.CodeLimitRefused, Message: err.Error()}
	}
	in.Request.Profile = p
	if in.NoReserve && r.Local.AllowNoReserve {
		r.Logger.Warn("execução sem reserva do sistema autorizada", "execucao", in.Request.RunID,
			"cpu_pct", p.CPUQuotaPercent, "memoria", p.MemoryMaxBytes)
	}

	dir := r.runDir(in.Request.RunID)
	if err := os.Mkdir(dir, 0o750); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, &ipc.Error{Code: ipc.CodeAlreadyExists, Message: "execução já existe"}
		}
		return nil, err
	}
	if r.CoreGID >= 0 {
		if err := os.Chown(dir, 0, r.CoreGID); err != nil {
			return nil, err
		}
	}
	if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // G302: o grupo do core lê os relatórios da execução
		return nil, err
	}
	data, _ := json.MarshalIndent(in.Request, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, report.RequestFile), data, 0o640); err != nil { //nolint:gosec // G306: o core (grupo) lê o pedido
		return nil, err
	}

	conn, err := r.dbus(ctx)
	if err != nil {
		return nil, err
	}
	sub, families, caps := "scan", []string{"AF_UNIX"}, uint64(runCapabilities)
	if in.Request.Kind == report.KindProcesses {
		// O inspetor lê /proc de todos os processos (SYS_PTRACE para /proc/PID/exe de outros usuários) e a rede
		// por netlink (sock_diag).
		sub, families, caps = "inspect", []string{"AF_UNIX", "AF_NETLINK"}, uint64(runCapabilities|1<<19)
	}
	props := []sddbus.Property{
		sddbus.PropDescription("VigiaHost: execução " + in.Request.RunID),
		sddbus.PropType("exec"),
		sddbus.PropExecStart([]string{r.Exe, sub, "-dir", dir, "-state", r.StateDir, "-user-rules", r.userRules()}, true),
		sddbus.PropSlice("vigiahost.slice"),
		prop("CollectMode", "inactive-or-failed"),
		prop("RuntimeMaxUSec", uint64(p.MaxRuntimeSec)*1_000_000), //nolint:gosec // validado por Enforce
		prop("Nice", int32(p.Nice)),                               //nolint:gosec // 0..19
		prop("TasksMax", uint64(512)),
		prop("UMask", uint32(0o027)),
		// Isolamento: sem rede, sistema só leitura, escrita só nos diretórios da execução, do cache e das regras.
		prop("PrivateNetwork", true),
		// Sem PrivateTmp: /tmp, /var/tmp e /dev/shm são onde malware costuma ficar e precisam ser varridos.
		prop("NoNewPrivileges", true),
		prop("ProtectSystem", "strict"),
		prop("ProtectHome", "read-only"),
		prop("ReadWritePaths", []string{dir, filepath.Join(r.StateDir, "cache"), filepath.Join(r.StateDir, "rules")}),
		prop("ProtectKernelTunables", true),
		prop("ProtectKernelModules", true),
		prop("ProtectControlGroups", true),
		prop("RestrictRealtime", true),
		prop("RestrictSUIDSGID", true),
		prop("LockPersonality", true),
		prop("RestrictAddressFamilies", struct {
			Allow    bool
			Families []string
		}{true, families}),
		prop("CapabilityBoundingSet", caps),
	}
	if r.CoreGID >= 0 {
		// Grupo primário do core: os relatórios nascem root:<grupo do core> (0640 com o UMask 027) e o core os lê.
		props = append(props, prop("Group", strconv.Itoa(r.CoreGID)))
	}
	props = append(props, limitProps(p)...)
	if p.IOReadBytesPerSec > 0 {
		props = append(props, prop("IOReadBandwidthMax", ioDevices(in.Request.Paths, uint64(p.IOReadBytesPerSec)))) //nolint:gosec // validado
	}
	unit := UnitName(in.Request.RunID)
	if _, err := conn.StartTransientUnitContext(ctx, unit, "fail", props, nil); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("criar a unidade %s: %w", unit, err)
	}
	r.Logger.Info("execução iniciada", "execucao", in.Request.RunID, "unidade", unit, "tipo", in.Request.Kind,
		"perfil", p.Name, "caminhos", len(in.Request.Paths))
	return r.state(ctx, in.Request.RunID)
}

type ioLimit struct {
	Path string
	BW   uint64
}

// ioDevices devolve o dispositivo de bloco de cada raiz para o limite de leitura (/dev/block/MAJ:MIN).
func ioDevices(paths []string, bw uint64) []ioLimit {
	seen := map[uint64]bool{}
	var out []ioLimit
	for _, p := range paths {
		var st syscall.Stat_t
		if syscall.Stat(p, &st) != nil || seen[st.Dev] {
			continue
		}
		seen[st.Dev] = true
		major := (st.Dev >> 8) & 0xfff
		minor := (st.Dev & 0xff) | ((st.Dev >> 12) & 0xfff00)
		out = append(out, ioLimit{Path: fmt.Sprintf("/dev/block/%d:%d", major, minor), BW: bw})
	}
	return out
}

func (r *Runs) ref(body json.RawMessage) (string, error) {
	var in ipc.RunRef
	if err := strictDecode(body, &in); err != nil {
		return "", err
	}
	if !runIDPattern.MatchString(in.RunID) {
		return "", &ipc.Error{Code: ipc.CodeBadRequest, Message: "identificador de execução inválido"}
	}
	return in.RunID, nil
}

// Status devolve o estado da unidade e o que a execução gravou.
func (r *Runs) Status(ctx context.Context, body json.RawMessage) (any, error) {
	id, err := r.ref(body)
	if err != nil {
		return nil, err
	}
	return r.state(ctx, id)
}

func (r *Runs) state(ctx context.Context, id string) (ipc.RunState, error) {
	dir := r.runDir(id)
	st := ipc.RunState{RunID: id, Unit: UnitName(id), Dir: dir, Active: "gone"}
	if _, err := os.Stat(dir); err != nil {
		return st, &ipc.Error{Code: ipc.CodeNotFound, Message: "execução desconhecida"}
	}
	if conn, err := r.dbus(ctx); err == nil {
		if props, err := conn.GetUnitPropertiesContext(ctx, st.Unit); err == nil && props["LoadState"] == "loaded" {
			st.Active, _ = props["ActiveState"].(string)
			st.Sub, _ = props["SubState"].(string)
			if fs, ok := props["FreezerState"].(string); ok {
				st.Frozen = fs == "frozen" || fs == "freezing"
			}
			if sp, err := conn.GetUnitTypePropertiesContext(ctx, st.Unit, "Service"); err == nil {
				st.Result, _ = sp["Result"].(string)
				if code, ok := sp["ExecMainStatus"].(int32); ok {
					st.ExitCode = int(code)
				}
			}
		}
	}
	var prog report.Progress
	if readJSON(filepath.Join(dir, report.ProgressFile), &prog) == nil {
		st.Progress = &prog
	}
	var sum report.Summary
	if readJSON(filepath.Join(dir, report.SummaryFile), &sum) == nil {
		st.Summary = &sum
	}
	return st, nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path) //nolint:gosec // diretório da execução
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// Cancel encerra o cgroup inteiro da execução.
func (r *Runs) Cancel(ctx context.Context, body json.RawMessage) (any, error) {
	id, err := r.ref(body)
	if err != nil {
		return nil, err
	}
	conn, err := r.dbus(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.StopUnitContext(ctx, UnitName(id), "replace", nil); err != nil && !isNoSuchUnit(err) {
		return nil, err
	}
	r.Logger.Info("execução cancelada", "execucao", id)
	return r.state(ctx, id)
}

// Pause congela a unidade pelo freezer do cgroup v2 (systemd 246 ou mais novo).
func (r *Runs) Pause(ctx context.Context, body json.RawMessage) (any, error) {
	return r.freeze(ctx, body, true)
}

// Resume descongela a unidade.
func (r *Runs) Resume(ctx context.Context, body json.RawMessage) (any, error) {
	return r.freeze(ctx, body, false)
}

func (r *Runs) freeze(ctx context.Context, body json.RawMessage, freeze bool) (any, error) {
	id, err := r.ref(body)
	if err != nil {
		return nil, err
	}
	conn, err := r.dbus(ctx)
	if err != nil {
		return nil, err
	}
	if freeze {
		err = conn.FreezeUnit(ctx, UnitName(id))
	} else {
		err = conn.ThawUnit(ctx, UnitName(id))
	}
	if err != nil {
		if isNoSuchUnit(err) {
			return nil, &ipc.Error{Code: ipc.CodeNotFound, Message: "execução não está rodando"}
		}
		if strings.Contains(err.Error(), "UnknownMethod") || strings.Contains(err.Error(), "not supported") {
			return nil, &ipc.Error{Code: ipc.CodeUnsupported, Message: "pausa exige systemd 246 e cgroup v2"}
		}
		return nil, err
	}
	r.Logger.Info("execução pausada ou retomada", "execucao", id, "pausada", freeze)
	return r.state(ctx, id)
}

// Limits ajusta CPU, memória e E/S da execução em andamento, com as mesmas travas do início.
func (r *Runs) Limits(ctx context.Context, body json.RawMessage) (any, error) {
	var in ipc.RunLimits
	if err := strictDecode(body, &in); err != nil {
		return nil, err
	}
	if !runIDPattern.MatchString(in.RunID) {
		return nil, &ipc.Error{Code: ipc.CodeBadRequest, Message: "identificador de execução inválido"}
	}
	p, err := profile.Enforce(in.Profile, r.Hardware, in.NoReserve, r.Local.AllowNoReserve)
	if err != nil {
		return nil, &ipc.Error{Code: ipc.CodeLimitRefused, Message: err.Error()}
	}
	conn, err := r.dbus(ctx)
	if err != nil {
		return nil, err
	}
	if err := conn.SetUnitPropertiesContext(ctx, UnitName(in.RunID), true, limitProps(p)...); err != nil {
		if isNoSuchUnit(err) {
			return nil, &ipc.Error{Code: ipc.CodeNotFound, Message: "execução não está rodando"}
		}
		return nil, err
	}
	r.Logger.Info("limites da execução ajustados", "execucao", in.RunID, "cpu_pct", p.CPUQuotaPercent, "memoria", p.MemoryMaxBytes)
	return r.state(ctx, in.RunID)
}

// List devolve todas as execuções com diretório no executor (para o core reconciliar depois de reiniciar).
func (r *Runs) List(ctx context.Context, _ json.RawMessage) (any, error) {
	entries, err := os.ReadDir(r.runsDir())
	if err != nil {
		return nil, err
	}
	out := ipc.RunList{Runs: []ipc.RunState{}}
	for _, e := range entries {
		if !e.IsDir() || !runIDPattern.MatchString(e.Name()) {
			continue
		}
		st, err := r.state(ctx, e.Name())
		if err != nil {
			continue
		}
		st.Progress = nil // a lista só precisa do estado; o resumo vem pelo status
		st.Summary = nil
		out.Runs = append(out.Runs, st)
	}
	return out, nil
}

// Cleanup apaga o diretório de uma execução que já terminou (retenção decidida pelo core).
func (r *Runs) Cleanup(ctx context.Context, body json.RawMessage) (any, error) {
	id, err := r.ref(body)
	if err != nil {
		return nil, err
	}
	st, err := r.state(ctx, id)
	if err != nil {
		return nil, err
	}
	if st.Active == "active" || st.Active == "activating" || st.Active == "deactivating" {
		return nil, &ipc.Error{Code: ipc.CodeBadRequest, Message: "execução ainda está rodando"}
	}
	if err := os.RemoveAll(r.runDir(id)); err != nil {
		return nil, err
	}
	return struct{}{}, nil
}

// HardwareInfo devolve o hardware e as capacidades para a tela de recursos.
func (r *Runs) HardwareInfo(ctx context.Context, _ json.RawMessage) (any, error) {
	h := ipc.Hardware{CPUs: r.Hardware.CPUs, MemoryBytes: r.Hardware.MemoryBytes, Rotational: r.Hardware.Rotational,
		AllowNoReserv: r.Local.AllowNoReserve}
	if conn, err := r.dbus(ctx); err == nil {
		if v, err := conn.GetManagerProperty("Version"); err == nil {
			h.Systemd = strings.Trim(v, `"`)
			n := leadingInt(h.Systemd) // "252-51.el9", "v255.4"
			_, cgErr := os.Stat("/sys/fs/cgroup/cgroup.controllers")
			h.Freezer = n >= 246 && cgErr == nil
		}
	}
	return h, nil
}

func isNoSuchUnit(err error) bool {
	var dbe dbus.Error
	if errors.As(err, &dbe) {
		return strings.HasSuffix(dbe.Name, "NoSuchUnit") || strings.HasSuffix(dbe.Name, "UnitNotLoaded")
	}
	return strings.Contains(err.Error(), "not loaded") || strings.Contains(err.Error(), "NoSuchUnit")
}

// strictDecode recusa campos desconhecidos: o core e o executor vêm do mesmo pacote.
func strictDecode(body json.RawMessage, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &ipc.Error{Code: ipc.CodeBadRequest, Message: "corpo inválido: " + err.Error()}
	}
	return nil
}

// Register acrescenta as operações de execução aos handlers do executor.
func (r *Runs) Register(h map[ipc.Op]Handler) {
	h[ipc.OpRunStart] = r.Start
	h[ipc.OpRunStatus] = r.Status
	h[ipc.OpRunCancel] = r.Cancel
	h[ipc.OpRunPause] = r.Pause
	h[ipc.OpRunResume] = r.Resume
	h[ipc.OpRunLimits] = r.Limits
	h[ipc.OpRunList] = r.List
	h[ipc.OpRunCleanup] = r.Cleanup
	h[ipc.OpHardware] = r.HardwareInfo
	h[ipc.OpAccounts] = r.Accounts
	h[ipc.OpRulesStatus] = r.RulesStatus
	h[ipc.OpRulesCompile] = r.RulesCompile
}

// Accounts lista as contas do servidor com os diretórios pessoais conferidos (o core não enxerga /home).
func (r *Runs) Accounts(ctx context.Context, _ json.RawMessage) (any, error) {
	list, lo, hi, err := accounts.Discover(ctx)
	if err != nil {
		return nil, err
	}
	return ipc.AccountList{UIDMin: lo, UIDMax: hi, Accounts: list}, nil
}

func leadingInt(s string) int {
	s = strings.TrimLeft(s, "v")
	end := strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' })
	if end >= 0 {
		s = s[:end]
	}
	n, _ := strconv.Atoi(s)
	return n
}
