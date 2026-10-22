package executor

import (
	"slices"
	"strings"
	"testing"

	"github.com/guigallina27/vigiahost/internal/report"
)

func TestValidacaoDosTiposDoSistema(t *testing.T) {
	for _, k := range []report.Kind{report.KindProcesses, report.KindIntegrity, report.KindUpdates} {
		req := report.Request{RunID: "20261022-120000-abcdef12", Kind: k}
		if err := ValidateRequest(&req, nil); err != nil {
			t.Errorf("%s: %v", k, err)
		}
		req.Paths = []string{"/etc"}
		if err := ValidateRequest(&req, nil); err == nil || !strings.Contains(err.Error(), "não recebe caminhos") {
			t.Errorf("%s com caminhos: %v", k, err)
		}
		req.Paths, req.Owners = nil, map[string][]uint32{"/tmp": {1}}
		if err := ValidateRequest(&req, nil); err == nil {
			t.Errorf("%s com filtro de dono aceito", k)
		}
	}
	req := report.Request{RunID: "20261022-120000-abcdef12", Kind: "rootkit"}
	if err := ValidateRequest(&req, nil); err == nil || !strings.Contains(err.Error(), "desconhecido") {
		t.Errorf("tipo desconhecido: %v", err)
	}
}

func TestUnidadePorTipo(t *testing.T) {
	all := func(string) bool { return true }
	none := func(string) bool { return false }

	files := SpecFor(report.KindFiles, LocalConfig{}, all)
	if files.Sub != "scan" || !files.PrivateNetwork || files.Caps != runCapabilities || len(files.Write) != 0 {
		t.Fatalf("arquivos: %+v", files)
	}

	procs := SpecFor(report.KindProcesses, LocalConfig{}, all)
	// Portas ocultas: rede do sistema, mas sem tráfego IP.
	if procs.Sub != "inspect" || procs.PrivateNetwork || !procs.IPDenyAll ||
		procs.Caps != runCapabilities|capSysPtrace|capNetBindService || !slices.Contains(procs.Families, "AF_INET6") {
		t.Fatalf("processos: %+v", procs)
	}

	integ := SpecFor(report.KindIntegrity, LocalConfig{RefreshPackageMetadata: true}, all)
	if integ.Sub != "integrity" || !integ.PrivateNetwork || integ.Caps != runCapabilities || len(integ.Args) != 0 || len(integ.Write) != 0 {
		t.Fatalf("integridade: %+v", integ)
	}

	upd := SpecFor(report.KindUpdates, LocalConfig{}, all)
	if upd.Sub != "updates" || !upd.PrivateNetwork || upd.IPDenyAll || len(upd.Args) != 0 ||
		!slices.Equal(upd.Write, []string{"/var/cache/dnf"}) || upd.Caps&capSetUID != 0 {
		t.Fatalf("atualizações sem rede: %+v", upd)
	}
	if u := SpecFor(report.KindUpdates, LocalConfig{}, none); len(u.Write) != 0 {
		t.Fatalf("diretório inexistente não entra em ReadWritePaths: %+v", u)
	}

	ref := SpecFor(report.KindUpdates, LocalConfig{RefreshPackageMetadata: true}, func(d string) bool { return d != "/var/lib/dnf" })
	if ref.PrivateNetwork || !slices.Equal(ref.Args, []string{"-refresh"}) || ref.Caps&capSetUID == 0 ||
		!slices.Equal(ref.Write, []string{"/var/cache/dnf", "/var/lib/apt/lists", "/var/cache/apt"}) {
		t.Fatalf("atualizações com lista nova: %+v", ref)
	}
}
