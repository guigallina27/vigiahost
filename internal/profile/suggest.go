package profile

import (
	"math"

	"github.com/guigallina27/vigiahost/internal/report"
)

// SuggestedName é o nome do perfil próprio criado ao aplicar a sugestão.
const SuggestedName = "sugerido"

// Load é a carga típica do servidor considerada na sugestão.
type Load struct {
	// PSI indica pressão legível (/proc/pressure); CPU, IO e Memory são a pressão "some" média de 5 minutos, em %.
	PSI    bool
	CPU    float64
	IO     float64
	Memory float64
	// LoadAvg é a carga média de 15 minutos (comparada ao número de núcleos).
	LoadAvg float64
	// Runs é quantas execuções recentes entraram no histórico; LimitedRatio, a fração do tempo delas com o ritmo
	// reduzido ou pausado por pressão (0 a 1).
	Runs         int
	LimitedRatio float64
}

// Reason explica uma decisão da sugestão. A interface traduz pelo código e preenche os valores.
type Reason struct {
	Code   string
	Values map[string]float64
}

// Suggestion é o perfil sugerido para o hardware e a carga, com a explicação de cada limite.
type Suggestion struct {
	Profile report.Profile
	Reasons []Reason
}

// Limiares de carga usados na sugestão.
const (
	busyCPUPressure  = 20  // % de pressão de CPU média que caracteriza servidor ocupado
	idleCPUPressure  = 5   // % abaixo da qual o servidor está folgado
	busyLoadPerCore  = 0.8 // carga de 15 min por núcleo
	idleLoadPerCore  = 0.3
	busyIOPressure   = 20
	busyMemPressure  = 10
	smallMemory      = 2 << 30
	limitedHistory   = 0.25 // fração do tempo limitada por pressão que pede menos paralelismo
	maxSuggestMemory = 4 << 30
)

// Suggest calcula um perfil a partir de núcleos, memória, tipo de disco, pressão típica e do histórico das
// execuções. O resultado sempre passa pelas travas (Enforce) sem liberação de reserva.
func Suggest(hw Hardware, load Load) Suggestion {
	cpus := max(hw.CPUs, 1)
	var reasons []Reason
	add := func(code string, kv ...any) {
		r := Reason{Code: code, Values: map[string]float64{}}
		for i := 0; i+1 < len(kv); i += 2 {
			name, _ := kv[i].(string)
			switch v := kv[i+1].(type) {
			case int:
				r.Values[name] = float64(v)
			case int64:
				r.Values[name] = float64(v)
			case float64:
				r.Values[name] = round1(v)
			}
		}
		reasons = append(reasons, r)
	}

	// CPU: fatia dos núcleos conforme a ocupação, sempre com um núcleo livre para o sistema.
	perCore := load.LoadAvg / float64(cpus)
	share, busy := 50, false
	switch {
	case (load.PSI && load.CPU >= busyCPUPressure) || perCore >= busyLoadPerCore:
		share, busy = 25, true
		add("cpu_busy", "cpus", cpus, "pressure", load.CPU, "load_per_core", perCore)
	case (!load.PSI || load.CPU < idleCPUPressure) && perCore < idleLoadPerCore:
		share = 75
		add("cpu_idle", "cpus", cpus, "pressure", load.CPU, "load_per_core", perCore)
	default:
		add("cpu_normal", "cpus", cpus, "pressure", load.CPU, "load_per_core", perCore)
	}
	cpuQuota := reserveCPU(cpus, max(minCPUQuotaPerc, cpus*share))
	reasons[len(reasons)-1].Values["quota"] = float64(cpuQuota)
	reasons[len(reasons)-1].Values["share"] = float64(share)

	// Memória: 40% da RAM até 4 GiB; menos em servidor pequeno ou com pressão de memória.
	pct, ceiling := int64(40), int64(maxSuggestMemory)
	code := "memory_normal"
	switch {
	case hw.MemoryBytes > 0 && hw.MemoryBytes < smallMemory:
		pct, code = 25, "memory_small"
	case load.PSI && load.Memory >= busyMemPressure:
		pct, ceiling, code = 25, 2<<30, "memory_pressure"
	}
	mem := max(int64(MinMemoryBytes), min(ceiling, hw.MemoryBytes*pct/100))
	mem = min(mem, hw.MemoryBytes*MemoryReservePct/100)
	mem = mem >> 20 << 20 // MiB inteiros
	add(code, "total", hw.MemoryBytes, "max", mem, "percent", pct, "pressure", load.Memory)

	// Disco: quantas leituras simultâneas e quanto peso de E/S o tipo aguenta sem atrasar os sites.
	var workers, ioWeight int
	var ioRead int64
	switch hw.Disk() {
	case DiskHDD:
		workers, ioWeight, ioRead = 2, 25, 50<<20
	case DiskNVMe:
		workers, ioWeight = min(8, max(2, cpus/2)), 100
	default:
		workers, ioWeight = min(4, max(2, cpus/2)), 50
	}
	add("disk_"+hw.Disk(), "workers", workers, "io_weight", ioWeight, "io_read", ioRead)

	// Workers acima dos núcleos liberados só disputam a mesma cota de CPU.
	if byCPU := max(1, int(math.Ceil(float64(cpuQuota)/100))); workers > byCPU {
		workers = byCPU
		add("workers_cpu", "workers", workers, "quota", cpuQuota)
	}
	if load.PSI && load.IO >= busyIOPressure {
		workers, ioWeight = max(1, workers/2), max(10, ioWeight/2)
		add("io_busy", "pressure", load.IO, "workers", workers, "io_weight", ioWeight)
	}
	if load.Runs > 0 && load.LimitedRatio >= limitedHistory {
		workers = max(1, workers/2)
		add("history_limited", "percent", load.LimitedRatio*100, "runs", load.Runs, "workers", workers)
	}

	nice := 10
	if busy {
		nice = 15
	}
	add("nice", "nice", nice)

	// Limiares de pressão: acima da pressão típica, para a varredura não ficar limitada o tempo todo num servidor
	// que já vive com alguma espera.
	pCPU := clampInt(int(math.Ceil(max(50, load.CPU+20))), 1, 90)
	pIO := clampInt(int(math.Ceil(max(40, load.IO+20))), 1, 90)
	pMem := clampInt(int(math.Ceil(max(20, load.Memory+10))), 1, 90)
	if load.PSI {
		add("pressure_thresholds", "cpu", pCPU, "io", pIO, "memory", pMem)
	} else {
		add("pressure_unavailable", "cpu", pCPU, "io", pIO, "memory", pMem)
	}

	p := report.Profile{
		Name: SuggestedName, CPUQuotaPercent: cpuQuota, MemoryMaxBytes: mem, IOReadBytesPerSec: ioRead,
		IOWeight: ioWeight, Workers: clampInt(workers, 1, MaxWorkers), ClamdConcurrency: clampInt(workers, 1, 4),
		MaxRuntimeSec: defaultRuntimeSec, Nice: nice, PressureCPU: pCPU, PressureIO: pIO, PressureMemory: pMem,
	}
	if enforced, err := Enforce(p, hw, false, false); err == nil {
		p = enforced
	} else if std, ok := Preset(hw, Standard); ok {
		// Não deveria acontecer: os cálculos acima já respeitam as travas. Fica o perfil padrão como rede.
		std.Name = SuggestedName
		p = std
	}
	return Suggestion{Profile: p, Reasons: reasons}
}

func clampInt(v, lo, hi int) int { return max(lo, min(hi, v)) }

func round1(v float64) float64 { return math.Round(v*10) / 10 }
