package profile

import (
	"errors"
	"testing"

	"github.com/guigallina27/vigiahost/internal/report"
)

var hw = Hardware{CPUs: 8, MemoryBytes: 16 << 30}

func TestPresetsRespeitamAsTravas(t *testing.T) {
	for _, h := range []Hardware{hw, {CPUs: 1, MemoryBytes: 1 << 30}, {CPUs: 64, MemoryBytes: 512 << 30, Rotational: true}} {
		for _, p := range Presets(h) {
			if _, err := Enforce(p, h, false, false); err != nil {
				t.Errorf("perfil %s em %+v recusado: %v", p.Name, h, err)
			}
		}
	}
}

func TestMemoriaAcimaDe75PorCentoRecusadaSemLiberacao(t *testing.T) {
	p, _ := Preset(hw, Standard)
	p.MemoryMaxBytes = hw.MemoryBytes * 80 / 100
	if _, err := Enforce(p, hw, false, false); !errors.Is(err, ErrRefused) {
		t.Fatalf("sem confirmação: %v", err)
	}
	// O pedido da API sozinho não basta: a configuração local precisa permitir.
	if _, err := Enforce(p, hw, true, false); !errors.Is(err, ErrRefused) {
		t.Fatalf("pedido sem permissão local: %v", err)
	}
	if _, err := Enforce(p, hw, true, true); err != nil {
		t.Fatalf("com as duas liberações: %v", err)
	}
}

func TestTodosOsNucleosRecusadoSemLiberacao(t *testing.T) {
	p, _ := Preset(hw, Intensive)
	p.CPUQuotaPercent = 800
	if _, err := Enforce(p, hw, false, false); !errors.Is(err, ErrRefused) {
		t.Fatal("todos os núcleos sem liberação deveria ser recusado")
	}
	p.CPUQuotaPercent = 900
	if _, err := Enforce(p, hw, true, true); !errors.Is(err, ErrRefused) {
		t.Fatal("acima do total de núcleos é sempre recusado")
	}
}

func TestValoresForaDaFaixaSempreRecusados(t *testing.T) {
	base, _ := Preset(hw, Standard)
	cases := map[string]func(p *report.Profile){
		"workers zero":   func(p *report.Profile) { p.Workers = 0 },
		"nice negativo":  func(p *report.Profile) { p.Nice = -5 },
		"tempo infinito": func(p *report.Profile) { p.MaxRuntimeSec = 0 },
		"clamd demais":   func(p *report.Profile) { p.ClamdConcurrency = 100 },
		"memória ínfima": func(p *report.Profile) { p.MemoryMaxBytes = 1 << 20 },
	}
	for name, mut := range cases {
		p := base
		mut(&p)
		if _, err := Enforce(p, hw, true, true); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
