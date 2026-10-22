package executor

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/controls"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/profile"
	"github.com/guigallina27/vigiahost/internal/report"
)

// Teste com systemd real: cria a unidade transitória, acompanha até o fim e confere os achados. Só roda como root
// numa máquina com systemd (laboratório); VIGIAHOST_SYSTEMD_TEST=1 habilita.
func TestExecucaoEmUnidadeTransitoria(t *testing.T) {
	if os.Getenv("VIGIAHOST_SYSTEMD_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("exige root, systemd e VIGIAHOST_SYSTEMD_TEST=1")
	}
	base, err := os.MkdirTemp("/var/tmp", "vh-teste-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	exe := filepath.Join(base, "vigiahost-executor")
	build := exec.Command("go", "build", "-o", exe, "../../cmd/vigiahost-executor")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "alvo")
	if err := os.MkdirAll(filepath.Join(target, "uploads"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(target, "uploads", "marcador.php"), controls.MarkerFile(), 0o644)
	_ = os.WriteFile(filepath.Join(target, "uploads", "eicar.com"), controls.EICAR(), 0o644)
	_ = os.WriteFile(filepath.Join(target, "limpo.txt"), controls.NegativeFile(), 0o644)

	hw := DetectHardware()
	runs := &Runs{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), StateDir: filepath.Join(base, "estado"), Exe: exe, CoreGID: 0, Hardware: hw}
	if err := runs.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	p, _ := profile.Preset(hw, profile.Standard)
	id := "teste-" + time.Now().Format("150405")
	body, _ := json.Marshal(ipc.RunStart{Request: report.Request{RunID: id, Kind: report.KindFiles, Paths: []string{target}, Profile: p}})
	ctx := context.Background()
	if _, err := runs.Start(ctx, body); err != nil {
		t.Fatal(err)
	}
	ref, _ := json.Marshal(ipc.RunRef{RunID: id})
	if _, err := runs.Start(ctx, body); err == nil {
		t.Fatal("o mesmo identificador não pode iniciar duas vezes")
	}
	deadline := time.Now().Add(5 * time.Minute)
	var st ipc.RunState
	for time.Now().Before(deadline) {
		out, err := runs.Status(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		st = out.(ipc.RunState)
		if st.Summary != nil && (st.Active == "gone" || st.Active == "inactive") {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if st.Summary == nil {
		t.Fatalf("execução não terminou: %+v", st)
	}
	if st.Summary.Status != report.StatusCompleted {
		t.Fatalf("estado %s: %+v", st.Summary.Status, st.Summary)
	}
	f, err := os.Open(filepath.Join(st.Dir, report.FindingsFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var sigs []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var fd report.Finding
		if json.Unmarshal(sc.Bytes(), &fd) == nil {
			sigs = append(sigs, fd.Signature+" "+fd.Location.Path)
		}
	}
	joined := strings.Join(sigs, "\n")
	if !strings.Contains(joined, controls.YARARuleName+" "+filepath.Join(target, "uploads", "marcador.php")) ||
		!strings.Contains(joined, "Eicar") {
		t.Fatalf("achados:\n%s", joined)
	}
	if strings.Contains(joined, "limpo.txt") {
		t.Fatal("controle negativo acusado")
	}

	// Pedido acima da reserva é recusado pela trava do executor, mesmo com NoReserve vindo da API.
	p.MemoryMaxBytes = hw.MemoryBytes * 90 / 100
	body, _ = json.Marshal(ipc.RunStart{Request: report.Request{RunID: id + "-x", Kind: report.KindFiles, Paths: []string{target}, Profile: p}, NoReserve: true})
	if _, err := runs.Start(ctx, body); err == nil || !strings.Contains(err.Error(), "limit_refused") {
		t.Fatalf("trava de memória: %v", err)
	}
	if _, err := runs.Cleanup(ctx, ref); err != nil {
		t.Fatal(err)
	}
}

// Pausa, retomada, ajuste de limites e cancelamento numa execução longa (o corpus sintético do laboratório).
func TestExecucaoPausaLimitesECancelamento(t *testing.T) {
	const corpus = "/var/tmp/corpus/benigno"
	if os.Getenv("VIGIAHOST_SYSTEMD_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("exige root, systemd e VIGIAHOST_SYSTEMD_TEST=1")
	}
	if _, err := os.Stat(corpus); err != nil {
		t.Skip("corpus benigno ausente")
	}
	base, err := os.MkdirTemp("/var/tmp", "vh-teste-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	exe := filepath.Join(base, "vigiahost-executor")
	if out, err := exec.Command("go", "build", "-o", exe, "../../cmd/vigiahost-executor").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	hw := DetectHardware()
	runs := &Runs{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), StateDir: filepath.Join(base, "estado"), Exe: exe, CoreGID: 0, Hardware: hw}
	if err := runs.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	p, _ := profile.Preset(hw, profile.Light)
	id := "longa-" + time.Now().Format("150405")
	body, _ := json.Marshal(ipc.RunStart{Request: report.Request{RunID: id, Kind: report.KindFiles, Paths: []string{corpus}, Profile: p}})
	ctx := context.Background()
	if _, err := runs.Start(ctx, body); err != nil {
		t.Fatal(err)
	}
	ref, _ := json.Marshal(ipc.RunRef{RunID: id})
	status := func() ipc.RunState {
		out, err := runs.Status(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		return out.(ipc.RunState)
	}
	// Espera começar a analisar.
	for i := 0; i < 120; i++ {
		if st := status(); st.Progress != nil && st.Progress.FilesProcessed > 0 {
			break
		}
		time.Sleep(time.Second)
	}
	hwInfo, _ := runs.HardwareInfo(ctx, nil)
	if hwInfo.(ipc.Hardware).Freezer {
		if _, err := runs.Pause(ctx, ref); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		before := status().Progress.FilesProcessed
		time.Sleep(3 * time.Second)
		st := status()
		if !st.Frozen || st.Progress.FilesProcessed != before {
			t.Fatalf("pausa não congelou: frozen=%v %d -> %d", st.Frozen, before, st.Progress.FilesProcessed)
		}
		if _, err := runs.Resume(ctx, ref); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Log("freezer indisponível; pausa não testada")
	}
	p2, _ := profile.Preset(hw, profile.Standard)
	lim, _ := json.Marshal(ipc.RunLimits{RunID: id, Profile: p2})
	if _, err := runs.Limits(ctx, lim); err != nil {
		t.Fatal(err)
	}
	if _, err := runs.Cancel(ctx, ref); err != nil {
		t.Fatal(err)
	}
	var st ipc.RunState
	for i := 0; i < 60; i++ {
		st = status()
		if st.Summary != nil && st.Active != "active" && st.Active != "deactivating" {
			break
		}
		time.Sleep(time.Second)
	}
	if st.Summary == nil || st.Summary.Status != report.StatusCanceled {
		t.Fatalf("cancelamento: %+v", st)
	}
}
