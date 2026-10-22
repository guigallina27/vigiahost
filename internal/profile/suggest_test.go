package profile

import (
	"errors"
	"slices"
	"testing"
)

func codes(s Suggestion) []string {
	var out []string
	for _, r := range s.Reasons {
		out = append(out, r.Code)
	}
	return out
}

func TestSugestaoSempreRespeitaAsTravas(t *testing.T) {
	hws := []Hardware{
		{CPUs: 1, MemoryBytes: 1 << 30},
		{CPUs: 2, MemoryBytes: 2 << 30, Rotational: true},
		{CPUs: 4, MemoryBytes: 8 << 30, DiskType: DiskSSD},
		{CPUs: 16, MemoryBytes: 64 << 30, DiskType: DiskNVMe},
		{CPUs: 128, MemoryBytes: 1 << 40, DiskType: DiskHDD},
	}
	loads := []Load{
		{},
		{PSI: true, CPU: 50, IO: 60, Memory: 40, LoadAvg: 300},
		{PSI: true, CPU: 1, LoadAvg: 0.1, Runs: 5, LimitedRatio: 0.9},
	}
	for _, hw := range hws {
		for _, ld := range loads {
			s := Suggest(hw, ld)
			if _, err := Enforce(s.Profile, hw, false, false); err != nil {
				t.Errorf("%+v %+v: sugestão recusada pelas travas: %v (%+v)", hw, ld, err, s.Profile)
			}
			if s.Profile.Name != SuggestedName || len(s.Reasons) < 4 {
				t.Errorf("sugestão incompleta: %+v", s)
			}
		}
	}
}

func TestSugestaoConformeDiscoECarga(t *testing.T) {
	hw := Hardware{CPUs: 8, MemoryBytes: 16 << 30, DiskType: DiskNVMe}
	idle := Suggest(hw, Load{PSI: true, CPU: 1, IO: 1, LoadAvg: 0.5})
	if idle.Profile.CPUQuotaPercent != 600 || idle.Profile.Workers != 4 || idle.Profile.IOWeight != 100 {
		t.Fatalf("servidor folgado com NVMe: %+v", idle.Profile)
	}
	if !slices.Contains(codes(idle), "cpu_idle") || !slices.Contains(codes(idle), "disk_nvme") {
		t.Fatalf("explicação: %v", codes(idle))
	}
	if idle.Profile.MemoryMaxBytes != 4<<30 {
		t.Fatalf("memória: 40%% de 16 GiB limitado a 4 GiB, veio %d", idle.Profile.MemoryMaxBytes)
	}

	busy := Suggest(hw, Load{PSI: true, CPU: 35, IO: 30, Memory: 15, LoadAvg: 10})
	if busy.Profile.CPUQuotaPercent != 200 || busy.Profile.Nice != 15 {
		t.Fatalf("servidor ocupado: %+v", busy.Profile)
	}
	if busy.Profile.Workers >= idle.Profile.Workers || busy.Profile.MemoryMaxBytes > 2<<30 {
		t.Fatalf("ocupado deveria ter menos workers e memória: %+v", busy.Profile)
	}
	for _, c := range []string{"cpu_busy", "io_busy", "memory_pressure", "pressure_thresholds"} {
		if !slices.Contains(codes(busy), c) {
			t.Errorf("faltou a explicação %s: %v", c, codes(busy))
		}
	}
	// Limiar acima da pressão típica, para não limitar o tempo todo.
	if busy.Profile.PressureCPU < 55 || busy.Profile.PressureIO < 50 {
		t.Fatalf("limiares: %+v", busy.Profile)
	}

	hdd := Suggest(Hardware{CPUs: 8, MemoryBytes: 16 << 30, Rotational: true}, Load{})
	if hdd.Profile.Workers != 2 || hdd.Profile.IOReadBytesPerSec != 50<<20 || !slices.Contains(codes(hdd), "disk_hdd") {
		t.Fatalf("disco rotacional: %+v %v", hdd.Profile, codes(hdd))
	}
	if !slices.Contains(codes(hdd), "pressure_unavailable") {
		t.Fatalf("sem PSI a explicação diz que a limitação não vai agir: %v", codes(hdd))
	}

	history := Suggest(hw, Load{PSI: true, CPU: 1, IO: 1, LoadAvg: 0.5, Runs: 4, LimitedRatio: 0.5})
	if history.Profile.Workers != idle.Profile.Workers/2 || !slices.Contains(codes(history), "history_limited") {
		t.Fatalf("histórico limitado: %+v %v", history.Profile, codes(history))
	}

	small := Suggest(Hardware{CPUs: 1, MemoryBytes: 1 << 30}, Load{})
	if small.Profile.CPUQuotaPercent > 75 || small.Profile.Workers != 1 || !slices.Contains(codes(small), "memory_small") {
		t.Fatalf("servidor pequeno: %+v %v", small.Profile, codes(small))
	}
}

func TestLimiaresDePressaoForaDaFaixa(t *testing.T) {
	p, _ := Preset(hw, Standard)
	if p.PressureCPU == 0 || p.PressureIO == 0 || p.PressureMemory == 0 {
		t.Fatalf("perfis pré-definidos ligam a limitação: %+v", p)
	}
	for _, v := range []int{-1, 101} {
		q := p
		q.PressureIO = v
		if _, err := Enforce(q, hw, true, true); !errors.Is(err, ErrRefused) {
			t.Errorf("pressão %d aceita", v)
		}
	}
	q := p
	q.PressureCPU, q.PressureIO, q.PressureMemory = 0, 0, 0
	if _, err := Enforce(q, hw, false, false); err != nil {
		t.Fatalf("zero desliga e é válido: %v", err)
	}
}

func TestTipoDeDisco(t *testing.T) {
	cases := map[Hardware]string{
		{DiskType: DiskNVMe}:              DiskNVMe,
		{Rotational: true}:                DiskHDD,
		{}:                                DiskSSD,
		{DiskType: "x", Rotational: true}: DiskHDD,
	}
	for h, want := range cases {
		if got := h.Disk(); got != want {
			t.Errorf("%+v: %s, esperado %s", h, got, want)
		}
	}
}
