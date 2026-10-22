package executor

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	sddbus "github.com/coreos/go-systemd/v22/dbus"

	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/profile"
	"github.com/guigallina27/vigiahost/internal/report"
)

// Ajuste em tempo real com systemd real: a unidade transitória de uma execução (aqui um sleep no lugar da varredura,
// para não depender de corpus) recebe os limites novos pelo D-Bus e o cgroup reflete a mudança. Só roda como root
// com VIGIAHOST_SYSTEMD_TEST=1 (laboratório).
func TestAjusteEmTempoRealNaUnidade(t *testing.T) {
	if os.Getenv("VIGIAHOST_SYSTEMD_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("exige root, systemd e VIGIAHOST_SYSTEMD_TEST=1")
	}
	base, err := os.MkdirTemp("/var/tmp", "vh-ajuste-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	hw := DetectHardware()
	runs := &Runs{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), StateDir: filepath.Join(base, "estado"), CoreGID: -1, Hardware: hw}
	if err := runs.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	ctx := context.Background()

	p, _ := profile.Preset(hw, profile.Standard)
	id := "ajuste-" + time.Now().Format("150405")
	dir := filepath.Join(runs.StateDir, "runs", id)
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(report.Request{RunID: id, Kind: report.KindFiles, Paths: []string{base}, Profile: p})
	if err := os.WriteFile(filepath.Join(dir, report.RequestFile), req, 0o640); err != nil {
		t.Fatal(err)
	}
	conn, err := sddbus.NewSystemConnectionContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	unit := UnitName(id)
	props := append([]sddbus.Property{
		sddbus.PropDescription("VigiaHost: teste de ajuste " + id),
		sddbus.PropExecStart([]string{"/bin/sleep", "300"}, false),
		sddbus.PropSlice("vigiahost.slice"),
		prop("CollectMode", "inactive-or-failed"),
	}, limitProps(p)...)
	if _, err := conn.StartTransientUnitContext(ctx, unit, "fail", props, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.StopUnitContext(context.Background(), unit, "replace", nil) })
	waitActive(t, conn, unit)

	show := func() map[string]string {
		t.Helper()
		out, err := exec.Command("systemctl", "show", unit, "-p", "CPUQuotaPerSecUSec", "-p", "MemoryMax", "-p", "MemoryHigh",
			"-p", "IOWeight", "-p", "IOReadBandwidthMax", "-p", "ControlGroup").Output()
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			k, v, _ := strings.Cut(line, "=")
			m[k] = v
		}
		return m
	}
	cgroupFile := func(cg, name string) string {
		b, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", cg, name))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}

	cpu, mem, weight, rbps := 50, int64(256<<20), 20, int64(10<<20)
	body, _ := json.Marshal(ipc.RunAdjust{RunID: id, CPUQuotaPercent: &cpu, MemoryMaxBytes: &mem, IOWeight: &weight, IOReadBytesPerSec: &rbps})
	out, err := runs.Adjust(ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	st := out.(ipc.RunState)
	if st.Limits == nil || st.Limits.CPUQuotaPercent != 50 || st.Limits.MemoryMaxBytes != mem || st.Limits.Workers != p.Workers {
		t.Fatalf("limites efetivos devolvidos: %+v", st.Limits)
	}
	got := show()
	if got["CPUQuotaPerSecUSec"] != "500ms" || got["MemoryMax"] != strconv.FormatInt(mem, 10) ||
		got["MemoryHigh"] != strconv.FormatInt(mem*3/4, 10) || got["IOWeight"] != "20" ||
		!strings.Contains(got["IOReadBandwidthMax"], strconv.FormatInt(rbps, 10)) {
		t.Fatalf("propriedades da unidade depois do ajuste: %v", got)
	}
	cg := got["ControlGroup"]
	if v := cgroupFile(cg, "cpu.max"); v != "" && v != "50000 100000" {
		t.Fatalf("cpu.max no cgroup: %q", v)
	}
	if v := cgroupFile(cg, "memory.max"); v != "" && v != strconv.FormatInt(mem, 10) {
		t.Fatalf("memory.max no cgroup: %q", v)
	}
	var saved report.Profile
	if err := readJSON(filepath.Join(dir, report.LimitsFile), &saved); err != nil || saved.CPUQuotaPercent != 50 {
		t.Fatalf("perfil efetivo não gravado: %+v %v", saved, err)
	}

	// Segundo ajuste parte do efetivo (não do pedido original) e tira o limite de banda.
	cpu2, zero := 75, int64(0)
	body, _ = json.Marshal(ipc.RunAdjust{RunID: id, CPUQuotaPercent: &cpu2, IOReadBytesPerSec: &zero})
	if _, err := runs.Adjust(ctx, body); err != nil {
		t.Fatal(err)
	}
	got = show()
	if got["CPUQuotaPerSecUSec"] != "750ms" || got["MemoryMax"] != strconv.FormatInt(mem, 10) || got["IOReadBandwidthMax"] != "" {
		t.Fatalf("segundo ajuste: %v", got)
	}

	// Trava: memória acima de 75% da RAM é recusada (mesmo pedindo "sem reserva" sem a liberação local) e nada muda.
	big := hw.MemoryBytes * 90 / 100
	body, _ = json.Marshal(ipc.RunAdjust{RunID: id, MemoryMaxBytes: &big, NoReserve: true})
	if _, err := runs.Adjust(ctx, body); err == nil || !strings.Contains(err.Error(), "limit_refused") {
		t.Fatalf("trava de memória: %v", err)
	}
	if show()["MemoryMax"] != strconv.FormatInt(mem, 10) {
		t.Fatal("pedido recusado alterou a unidade")
	}
	// Campo fora do tipo é recusado pelo decodificador.
	if _, err := runs.Adjust(ctx, json.RawMessage(`{"run_id":"`+id+`","workers":64}`)); err == nil {
		t.Fatal("campo desconhecido aceito")
	}

	// Unidade parada: o ajuste responde "não está rodando".
	if _, err := conn.StopUnitContext(ctx, unit, "replace", nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	body, _ = json.Marshal(ipc.RunAdjust{RunID: id, CPUQuotaPercent: &cpu})
	if _, err := runs.Adjust(ctx, body); err == nil || !strings.Contains(err.Error(), "not_found") {
		t.Fatalf("ajuste em execução parada: %v", err)
	}
	// Execução que o executor não conhece.
	body, _ = json.Marshal(ipc.RunAdjust{RunID: "nao-existe", CPUQuotaPercent: &cpu})
	if _, err := runs.Adjust(ctx, body); err == nil || !strings.Contains(err.Error(), "not_found") {
		t.Fatalf("execução desconhecida: %v", err)
	}
}

func waitActive(t *testing.T, conn *sddbus.Conn, unit string) {
	t.Helper()
	for range 50 {
		p, err := conn.GetUnitPropertiesContext(context.Background(), unit)
		if err == nil && p["ActiveState"] == "active" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("unidade %s não ficou ativa", unit)
}
