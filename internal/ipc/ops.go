package ipc

import "github.com/guigallina27/vigiahost/internal/report"

// Operações das execuções (Fase 1A). Volumes grandes (achados, progresso) ficam em arquivos no diretório da
// execução; pelo socket só passa controle (ADR-014).
const (
	OpRunStart   Op = "run.start"
	OpRunStatus  Op = "run.status"
	OpRunCancel  Op = "run.cancel"
	OpRunPause   Op = "run.pause"
	OpRunResume  Op = "run.resume"
	OpRunLimits  Op = "run.limits"
	OpRunList    Op = "run.list"
	OpEngines    Op = "engines.status"
	OpHardware   Op = "hardware"
	OpRunCleanup Op = "run.cleanup"
)

// Códigos de erro das operações de execução.
const (
	CodeNotFound      = "not_found"
	CodeAlreadyExists = "already_exists"
	CodeLimitRefused  = "limit_refused"
	CodePathRefused   = "path_refused"
	CodeUnsupported   = "unsupported"
)

// RunStart pede uma execução nova. O executor revalida tudo: identificador, caminhos e perfil.
type RunStart struct {
	Request report.Request `json:"request"`
	// NoReserve pede limites acima da reserva do sistema; só vale se a configuração local do executor permitir
	// (a API sozinha não consegue contornar a trava, ADR-012).
	NoReserve bool `json:"no_reserve,omitempty"`
}

// RunRef identifica uma execução.
type RunRef struct {
	RunID string `json:"run_id"`
}

// RunState é o estado da unidade transitória e do que a execução gravou.
type RunState struct {
	RunID    string           `json:"run_id"`
	Unit     string           `json:"unit"`
	Dir      string           `json:"dir"`
	Active   string           `json:"active"`    // active, activating, deactivating, inactive, failed, gone
	Sub      string           `json:"sub"`       // running, exited, dead...
	Result   string           `json:"result"`    // success, exit-code, signal, timeout, oom-kill...
	Frozen   bool             `json:"frozen"`    // pausada pelo freezer do cgroup
	ExitCode int              `json:"exit_code"` // do processo principal, quando terminou
	Progress *report.Progress `json:"progress,omitempty"`
	Summary  *report.Summary  `json:"summary,omitempty"`
}

// RunLimits ajusta limites de uma execução em andamento (propriedades de cgroup em tempo real).
type RunLimits struct {
	RunID     string         `json:"run_id"`
	Profile   report.Profile `json:"profile"`
	NoReserve bool           `json:"no_reserve,omitempty"`
}

// RunList devolve as execuções conhecidas pelo executor (unidades e diretórios), para reconciliação.
type RunList struct {
	Runs []RunState `json:"runs"`
}

// Hardware descreve o servidor para sugerir perfis e aplicar as travas.
type Hardware struct {
	CPUs          int    `json:"cpus"`
	MemoryBytes   int64  `json:"memory_bytes"`
	Rotational    bool   `json:"rotational"`
	AllowNoReserv bool   `json:"allow_no_reserve"`
	Systemd       string `json:"systemd_version"`
	Freezer       bool   `json:"freezer"`
}
