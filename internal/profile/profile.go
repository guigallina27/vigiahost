// Package profile define os perfis de recursos (Leve, Padrão, Intensivo e próprios) e as travas que o executor
// aplica a qualquer pedido (ADR-012, escopo seção 12): nunca todos os núcleos e nunca mais de 75% da RAM sem a
// liberação explícita configurada localmente no executor.
package profile

import (
	"errors"
	"fmt"

	"github.com/guigallina27/vigiahost/internal/report"
)

// Nomes dos perfis padrão.
const (
	Light     = "leve"
	Standard  = "padrao"
	Intensive = "intensivo"
)

// Limites absolutos, valham ou não as reservas.
const (
	MaxRuntimeSec     = 48 * 3600
	MaxWorkers        = 64
	MaxClamdConc      = 16
	MemoryReservePct  = 75 // máximo de RAM sem liberação
	MinMemoryBytes    = 128 << 20
	DefaultMaxFileB   = 0
	minCPUQuotaPerc   = 10
	defaultRuntimeSec = 12 * 3600
)

// Hardware é o que importa do servidor para os perfis.
type Hardware struct {
	CPUs        int
	MemoryBytes int64
	Rotational  bool
}

// Presets devolve os perfis padrão calculados para o hardware.
func Presets(hw Hardware) []report.Profile {
	cpus := max(hw.CPUs, 1)
	mem := hw.MemoryBytes
	memMax := func(want int64, pct int64) int64 {
		return max(MinMemoryBytes, min(want, mem*pct/100))
	}
	workersIntensive := max(1, cpus-1)
	if hw.Rotational {
		workersIntensive = min(workersIntensive, 2) // disco rotacional: poucas leituras simultâneas
	}
	return []report.Profile{
		{
			Name: Light, CPUQuotaPercent: max(minCPUQuotaPerc, min(50, cpus*100/4)),
			MemoryMaxBytes: memMax(1<<30, 25), IOWeight: 10, Workers: 1, ClamdConcurrency: 1,
			MaxRuntimeSec: 24 * 3600, Nice: 19,
		},
		{
			Name: Standard, CPUQuotaPercent: reserveCPU(cpus, max(100, cpus*100/2)),
			MemoryMaxBytes: memMax(2<<30, 40), IOWeight: 50, Workers: min(2, cpus), ClamdConcurrency: 2,
			MaxRuntimeSec: defaultRuntimeSec, Nice: 10,
		},
		{
			Name: Intensive, CPUQuotaPercent: reserveCPU(cpus, cpus*100),
			MemoryMaxBytes: memMax(4<<30, 60), IOWeight: 100, Workers: workersIntensive, ClamdConcurrency: 4,
			MaxRuntimeSec: defaultRuntimeSec, Nice: 5,
		},
	}
}

// Preset devolve o perfil padrão pelo nome.
func Preset(hw Hardware, name string) (report.Profile, bool) {
	for _, p := range Presets(hw) {
		if p.Name == name {
			return p, true
		}
	}
	return report.Profile{}, false
}

// reserveCPU deixa um núcleo livre quando há mais de um (com um só, no máximo 75% dele).
func reserveCPU(cpus, want int) int {
	limit := (cpus - 1) * 100
	if cpus <= 1 {
		limit = 75
	}
	return max(minCPUQuotaPerc, min(want, limit))
}

// ErrRefused indica pedido acima das travas.
var ErrRefused = errors.New("limite recusado")

// Enforce confere o perfil pedido contra o hardware. Valores fora da faixa técnica são recusados; acima da
// reserva do sistema só passam com noReserve e allowNoReserve (configuração local do executor) ao mesmo tempo.
func Enforce(p report.Profile, hw Hardware, noReserve, allowNoReserve bool) (report.Profile, error) {
	cpus := max(hw.CPUs, 1)
	bypass := noReserve && allowNoReserve
	refuse := func(format string, args ...any) (report.Profile, error) {
		return report.Profile{}, fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
	}
	switch {
	case p.CPUQuotaPercent < 0 || p.MemoryMaxBytes < 0 || p.IOReadBytesPerSec < 0 || p.MaxFileBytes < 0:
		return refuse("valores negativos")
	case p.Workers < 1 || p.Workers > MaxWorkers:
		return refuse("workers deve ficar entre 1 e %d", MaxWorkers)
	case p.ClamdConcurrency < 1 || p.ClamdConcurrency > MaxClamdConc:
		return refuse("requisições simultâneas ao clamd devem ficar entre 1 e %d", MaxClamdConc)
	case p.Nice < 0 || p.Nice > 19:
		return refuse("prioridade (nice) deve ficar entre 0 e 19")
	case p.IOWeight != 0 && (p.IOWeight < 1 || p.IOWeight > 10000):
		return refuse("peso de E/S deve ficar entre 1 e 10000")
	case p.MaxRuntimeSec < 60 || p.MaxRuntimeSec > MaxRuntimeSec:
		return refuse("tempo máximo deve ficar entre 1 minuto e %d horas", MaxRuntimeSec/3600)
	case p.MemoryMaxBytes != 0 && p.MemoryMaxBytes < MinMemoryBytes:
		return refuse("memória máxima abaixo de %d MiB", MinMemoryBytes>>20)
	case p.CPUQuotaPercent != 0 && p.CPUQuotaPercent < minCPUQuotaPerc:
		return refuse("CPU abaixo de %d%%", minCPUQuotaPerc)
	case p.CPUQuotaPercent > cpus*100:
		return refuse("CPU acima do total de núcleos (%d%%)", cpus*100)
	}
	if !bypass {
		if p.CPUQuotaPercent == 0 || p.CPUQuotaPercent > reserveCPU(cpus, cpus*100) {
			return refuse("CPU acima da reserva do sistema: no máximo %d%% sem liberação", reserveCPU(cpus, cpus*100))
		}
		limit := hw.MemoryBytes * MemoryReservePct / 100
		if p.MemoryMaxBytes == 0 || p.MemoryMaxBytes > limit {
			return refuse("memória acima de %d%% da RAM sem liberação", MemoryReservePct)
		}
	}
	if p.IOWeight == 0 {
		p.IOWeight = 100
	}
	return p, nil
}
