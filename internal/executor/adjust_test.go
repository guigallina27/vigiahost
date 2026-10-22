package executor

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/profile"
)

func TestAjusteJuntaAoPerfilEfetivoEAplicaAsTravas(t *testing.T) {
	hw := profile.Hardware{CPUs: 4, MemoryBytes: 8 << 30}
	cur, _ := profile.Preset(hw, profile.Standard)
	cpu, mem := 100, int64(1<<30)
	p, err := MergeAdjust(cur, ipc.RunAdjust{RunID: "x", CPUQuotaPercent: &cpu, MemoryMaxBytes: &mem}, hw, false)
	if err != nil {
		t.Fatal(err)
	}
	if p.CPUQuotaPercent != 100 || p.MemoryMaxBytes != 1<<30 || p.Workers != cur.Workers || p.Nice != cur.Nice ||
		p.PressureIO != cur.PressureIO || p.IOWeight != cur.IOWeight {
		t.Fatalf("só CPU e memória deveriam mudar: %+v", p)
	}

	refused := func(adj ipc.RunAdjust, allow bool) {
		t.Helper()
		_, err := MergeAdjust(cur, adj, hw, allow)
		var ie *ipc.Error
		if !errors.As(err, &ie) || ie.Code != ipc.CodeLimitRefused {
			t.Fatalf("%+v deveria ser recusado pelas travas: %v", adj, err)
		}
	}
	all := 400 // todos os núcleos
	refused(ipc.RunAdjust{CPUQuotaPercent: &all}, false)
	refused(ipc.RunAdjust{CPUQuotaPercent: &all, NoReserve: true}, false) // o pedido sozinho não basta
	big := int64(7 << 30)                                                 // mais de 75% da RAM
	refused(ipc.RunAdjust{MemoryMaxBytes: &big}, false)
	tiny := int64(1 << 20)
	refused(ipc.RunAdjust{MemoryMaxBytes: &tiny, NoReserve: true}, true) // faixa técnica vale sempre
	zero := 0
	refused(ipc.RunAdjust{IOWeight: &zero}, false)
	over := 10001
	refused(ipc.RunAdjust{IOWeight: &over}, false)
	if _, err := MergeAdjust(cur, ipc.RunAdjust{CPUQuotaPercent: &all, NoReserve: true}, hw, true); err != nil {
		t.Fatalf("com o pedido e a liberação local: %v", err)
	}
	if _, err := MergeAdjust(cur, ipc.RunAdjust{RunID: "x"}, hw, false); err == nil {
		t.Fatal("ajuste vazio deveria ser recusado")
	}
}

func TestAjusteSoAceitaCamposPermitidos(t *testing.T) {
	// O decodificador do executor recusa campos fora do tipo: workers, nice e caminhos não mudam por aqui.
	var in ipc.RunAdjust
	for _, body := range []string{
		`{"run_id":"x","workers":64}`,
		`{"run_id":"x","profile":{"cpu_quota_percent":400}}`,
		`{"run_id":"x","exec_start":"/bin/sh"}`,
	} {
		if err := strictDecode(json.RawMessage(body), &in); err == nil || !strings.Contains(err.Error(), "bad_request") {
			t.Errorf("%s aceito: %v", body, err)
		}
	}
	if err := strictDecode(json.RawMessage(`{"run_id":"x","io_weight":50}`), &in); err != nil || in.IOWeight == nil || *in.IOWeight != 50 {
		t.Fatalf("campo permitido: %v %+v", err, in)
	}
}

func TestTipoDeDiscoPeloMaisLento(t *testing.T) {
	cases := []struct {
		names []string
		rot   map[string]bool
		want  string
	}{
		{nil, nil, ""},
		{[]string{"nvme0n1", "nvme1n1"}, nil, profile.DiskNVMe},
		{[]string{"nvme0n1", "sda"}, nil, profile.DiskSSD},
		{[]string{"nvme0n1", "sda"}, map[string]bool{"sda": true}, profile.DiskHDD},
		{[]string{"vda"}, nil, profile.DiskSSD},
	}
	for _, c := range cases {
		if got := DiskType(c.names, c.rot); got != c.want {
			t.Errorf("%v %v: %q, esperado %q", c.names, c.rot, got, c.want)
		}
	}
}
