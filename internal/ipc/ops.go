package ipc

import (
	"github.com/guigallina27/vigiahost/internal/accounts"
	"github.com/guigallina27/vigiahost/internal/perf"
	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/rules"
)

// AccountList é a resposta de OpAccounts: contas e a faixa de UID das contas humanas/de hospedagem.
type AccountList struct {
	UIDMin   uint32             `json:"uid_min"`
	UIDMax   uint32             `json:"uid_max"`
	Accounts []accounts.Account `json:"accounts"`
}

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
	// OpAccounts lista as contas do servidor (protocolo 1.1; executores 1.0 respondem "operação desconhecida").
	OpAccounts Op = "accounts.list"
	// OpRunAdjust ajusta limites de CPU, memória e E/S de uma execução em andamento, campo a campo (protocolo 1.2).
	OpRunAdjust Op = "run.adjust"
	// OpRulesStatus lista as fontes de regras YARA e o resultado da última compilação; OpRulesCompile pede uma
	// compilação com validação numa unidade transitória isolada (protocolo 1.3).
	OpRulesStatus  Op = "rules.status"
	OpRulesCompile Op = "rules.compile"
)

// RulesCompile pede a compilação do conjunto; Disabled são as fontes desativadas pelo administrador.
type RulesCompile struct {
	Disabled []string `json:"disabled,omitempty"`
}

// RulesStatus descreve as fontes de regras e a compilação.
type RulesStatus struct {
	UserDir string               `json:"user_dir"`
	Sources []rules.SourceInfo   `json:"sources"`
	Last    *rules.CompileStatus `json:"last,omitempty"`
	// Compiling indica a unidade de compilação pedida pelo administrador ainda rodando.
	Compiling bool `json:"compiling"`
}

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
	// Limits é o perfil efetivo depois dos ajustes em tempo real (nil sem ajuste; vale o do pedido).
	Limits *report.Profile `json:"limits,omitempty"`
}

// RunLimits ajusta limites de uma execução em andamento (propriedades de cgroup em tempo real).
type RunLimits struct {
	RunID     string         `json:"run_id"`
	Profile   report.Profile `json:"profile"`
	NoReserve bool           `json:"no_reserve,omitempty"`
}

// RunAdjust muda limites de uma execução em andamento. Só estes campos existem: o executor junta-os ao perfil efetivo
// que ele mesmo gravou para a execução, aplica as travas (reserva do sistema, faixas) ao resultado e só então chama
// SetUnitProperties na unidade. Campo ausente mantém o valor atual.
type RunAdjust struct {
	RunID             string `json:"run_id"`
	CPUQuotaPercent   *int   `json:"cpu_quota_percent,omitempty"`
	MemoryMaxBytes    *int64 `json:"memory_max_bytes,omitempty"`
	IOReadBytesPerSec *int64 `json:"io_read_bytes_per_sec,omitempty"`
	IOWeight          *int   `json:"io_weight,omitempty"`
	// NoReserve pede limites acima da reserva; só vale com a liberação na configuração local do executor.
	NoReserve bool `json:"no_reserve,omitempty"`
}

// Empty diz se o ajuste não muda nada.
func (a RunAdjust) Empty() bool {
	return a.CPUQuotaPercent == nil && a.MemoryMaxBytes == nil && a.IOReadBytesPerSec == nil && a.IOWeight == nil
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
	// Campos do protocolo 1.2 (ausentes em executores mais antigos).
	DiskType string         `json:"disk_type,omitempty"` // hdd, ssd ou nvme
	Pressure *perf.Pressure `json:"pressure,omitempty"`  // pressão do servidor no momento da consulta
	LoadAvg  float64        `json:"load_avg,omitempty"`  // carga média de 15 minutos
}
