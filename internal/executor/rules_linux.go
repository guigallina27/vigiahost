package executor

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	sddbus "github.com/coreos/go-systemd/v22/dbus"

	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/rules"
)

// RulesUnit é a unidade transitória da compilação de regras pedida pelo administrador (uma por vez).
const RulesUnit = "vigiahost-rules.service"

func (r *Runs) userRules() string {
	if r.UserRules != "" {
		return r.UserRules
	}
	return rules.UserDir
}

// RulesStatus lista as fontes (só leitura dos arquivos) e o resultado da última compilação, de execução ou pedida.
func (r *Runs) RulesStatus(ctx context.Context, _ json.RawMessage) (any, error) {
	st := ipc.RulesStatus{UserDir: r.userRules(), Sources: rules.Inspect(r.userRules())}
	if last, err := rules.ReadStatus(filepath.Join(r.StateDir, "rules")); err == nil {
		st.Last = last
	}
	st.Compiling = r.rulesCompiling(ctx)
	return st, nil
}

func (r *Runs) rulesCompiling(ctx context.Context) bool {
	conn, err := r.dbus(ctx)
	if err != nil {
		return false
	}
	props, err := conn.GetUnitPropertiesContext(ctx, RulesUnit)
	if err != nil || props["LoadState"] != "loaded" {
		return false
	}
	switch props["ActiveState"] {
	case "active", "activating", "deactivating", "reloading":
		return true
	}
	return false
}

// RulesCompile compila e valida o conjunto numa unidade transitória com o mesmo isolamento das execuções: sem
// rede, sistema só leitura e escrita só no diretório das regras compiladas. O YARA-X precisa de memória executável
// (vetada no serviço do executor) e as regras locais são entrada não confiável (escopo, seção 7.3).
func (r *Runs) RulesCompile(ctx context.Context, body json.RawMessage) (any, error) {
	var in ipc.RulesCompile
	if len(body) > 0 {
		if err := strictDecode(body, &in); err != nil {
			return nil, err
		}
	}
	if err := rules.ValidDisabled(in.Disabled); err != nil {
		return nil, &ipc.Error{Code: ipc.CodeBadRequest, Message: err.Error()}
	}
	if r.rulesCompiling(ctx) {
		return nil, &ipc.Error{Code: ipc.CodeAlreadyExists, Message: "compilação de regras já em andamento"}
	}
	conn, err := r.dbus(ctx)
	if err != nil {
		return nil, err
	}
	// Um núcleo, até 2 GiB (ou um quarto da memória) e 15 minutos.
	mem := uint64(2 << 30)
	if q := uint64(r.Hardware.MemoryBytes / 4); q > 256<<20 && q < mem { //nolint:gosec // memória detectada, positiva
		mem = q
	}
	exec := []string{r.Exe, "rules", "-state", r.StateDir, "-user-rules", r.userRules()}
	if len(in.Disabled) > 0 {
		exec = append(exec, "-disabled", strings.Join(in.Disabled, ","))
	}
	props := []sddbus.Property{
		sddbus.PropDescription("VigiaHost: compilação de regras YARA"),
		sddbus.PropType("exec"),
		sddbus.PropExecStart(exec, true),
		sddbus.PropSlice("vigiahost.slice"),
		prop("CollectMode", "inactive-or-failed"),
		prop("RuntimeMaxUSec", uint64(15*60)*1_000_000),
		prop("Nice", int32(10)),
		prop("TasksMax", uint64(64)),
		prop("UMask", uint32(0o077)),
		prop("CPUQuotaPerSecUSec", uint64(1_000_000)),
		prop("MemoryMax", mem),
		prop("PrivateNetwork", true),
		prop("PrivateTmp", true),
		prop("NoNewPrivileges", true),
		prop("ProtectSystem", "strict"),
		prop("ProtectHome", "read-only"),
		prop("ReadWritePaths", []string{filepath.Join(r.StateDir, "rules")}),
		prop("ProtectKernelTunables", true),
		prop("ProtectKernelModules", true),
		prop("ProtectControlGroups", true),
		prop("RestrictRealtime", true),
		prop("RestrictSUIDSGID", true),
		prop("LockPersonality", true),
		prop("RestrictAddressFamilies", struct {
			Allow    bool
			Families []string
		}{true, []string{"AF_UNIX"}}),
		prop("CapabilityBoundingSet", uint64(0)),
	}
	if _, err := conn.StartTransientUnitContext(ctx, RulesUnit, "fail", props, nil); err != nil {
		return nil, err
	}
	r.Logger.Info("compilação de regras iniciada", "unidade", RulesUnit, "desativadas", strings.Join(in.Disabled, ","))
	return r.RulesStatus(ctx, nil)
}
