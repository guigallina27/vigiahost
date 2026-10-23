// Package report define o que uma execução grava no seu diretório de saída e o core lê depois:
// pedido (request.json), progresso (progress.json), achados (findings.ndjson) e resumo (summary.json).
//
// Volumes grandes não passam pelo socket do executor (ADR-014): ficam nesses arquivos. O core trata tudo como
// entrada não confiável, porque caminhos e nomes de regra vêm de arquivos controlados pelas contas.
package report

import (
	"encoding/hex"
	"time"
	"unicode/utf8"
)

// Nomes dos arquivos no diretório de saída da execução.
const (
	RequestFile  = "request.json"
	ProgressFile = "progress.json"
	FindingsFile = "findings.ndjson"
	SummaryFile  = "summary.json"
	// LimitsFile guarda o perfil efetivo depois de ajustes em tempo real (gravado só pelo executor).
	LimitsFile = "limits.json"
	// Instantâneos da inspeção de processos.
	ProcessesFile   = "processes.json"
	PersistenceFile = "persistence.json"
	// HiddenFile é o resultado da busca por processos e portas ocultos (inspeção de processos).
	HiddenFile = "hidden.json"
	// IntegrityFile é o relatório da verificação contra os pacotes (execução de integridade).
	IntegrityFile = "integrity.json"
	// UpdatesFile é o relatório de correções pendentes e reinícios (execução de atualizações).
	UpdatesFile = "updates.json"
)

// Kind é o tipo de execução.
type Kind string

const (
	KindFiles     Kind = "files"     // varredura de arquivos com os motores
	KindProcesses Kind = "processes" // inspeção de processos, rede e persistência
	KindIntegrity Kind = "integrity" // arquivos conferidos contra os pacotes instalados (protocolo 1.2)
	KindUpdates   Kind = "updates"   // correções pendentes, serviços a reiniciar e reinício pendente (protocolo 1.2)
)

// Kinds lista os tipos de execução conhecidos, na ordem de despacho.
var Kinds = []Kind{KindFiles, KindProcesses, KindIntegrity, KindUpdates}

// ValidKind diz se o tipo é conhecido.
func ValidKind(k Kind) bool {
	for _, x := range Kinds {
		if x == k {
			return true
		}
	}
	return false
}

// Request é o pedido de execução que o core entrega ao executor; o executor revalida tudo pela própria política.
type Request struct {
	RunID   string   `json:"run_id"`
	Kind    Kind     `json:"kind"`
	Paths   []string `json:"paths,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
	// Owners restringe raízes de Paths a arquivos destes donos: na verificação por conta, /tmp, /var/tmp e /dev/shm
	// entram só com os arquivos do UID da conta (escopo, seção 9.1).
	Owners map[string][]uint32 `json:"owners,omitempty"`
	// Incremental reaproveita o cache: objeto inalterado já analisado com as mesmas versões não é relido.
	Incremental bool    `json:"incremental"`
	Profile     Profile `json:"profile"`
	// LMD liga o estágio do Linux Malware Detect (fonte adicional de assinaturas, ADR-023); desligado por padrão.
	LMD bool `json:"lmd,omitempty"`
	// DisabledRuleSources são fontes de regras YARA desativadas pelo administrador (nomes; o executor confere).
	DisabledRuleSources []string `json:"disabled_rule_sources,omitempty"`
}

// Profile é o perfil de recursos efetivo da execução (escopo, seção 12).
type Profile struct {
	Name string `json:"name"`
	// CPUQuotaPercent é a soma de núcleos em porcentagem (200 = dois núcleos inteiros).
	CPUQuotaPercent int   `json:"cpu_quota_percent"`
	MemoryMaxBytes  int64 `json:"memory_max_bytes"`
	// IOReadBytesPerSec 0 significa sem limite de banda (só peso).
	IOReadBytesPerSec int64 `json:"io_read_bytes_per_sec"`
	IOWeight          int   `json:"io_weight"`
	Workers           int   `json:"workers"`
	ClamdConcurrency  int   `json:"clamd_concurrency"`
	MaxRuntimeSec     int   `json:"max_runtime_sec"`
	Nice              int   `json:"nice"`
	// MaxFileBytes é o limite de tamanho por arquivo para a fila normal; acima disso vai para a fila de grandes.
	MaxFileBytes int64 `json:"max_file_bytes"`
	// Limiares de pressão (PSI "some" avg10, em %) acima dos quais a execução reduz o paralelismo e, persistindo,
	// pausa entre lotes até a pressão cair (escopo, seção 12). Zero desliga a limitação por aquele recurso.
	PressureCPU    int `json:"pressure_cpu,omitempty"`
	PressureIO     int `json:"pressure_io,omitempty"`
	PressureMemory int `json:"pressure_memory,omitempty"`
}

// PressureEnabled diz se algum limiar de pressão está ligado.
func (p Profile) PressureEnabled() bool {
	return p.PressureCPU > 0 || p.PressureIO > 0 || p.PressureMemory > 0
}

// Phase é a etapa corrente da execução, mostrada no progresso.
type Phase string

const (
	PhaseSelfTest  Phase = "selftest"
	PhaseInventory Phase = "inventory"
	PhaseScanning  Phase = "scanning"
	PhaseLarge     Phase = "large_files"
	PhaseLMD       Phase = "lmd"
	PhaseInspect   Phase = "inspect"
	PhaseHidden    Phase = "hidden"     // busca por processos e portas ocultos
	PhaseVerify    Phase = "verify"     // arquivos conferidos contra o banco de pacotes
	PhaseSignature Phase = "signatures" // assinaturas de pacotes e repositórios
	PhaseUpdates   Phase = "updates"    // correções pendentes no cache do gerenciador de pacotes
	PhaseRestart   Phase = "restart"    // serviços e kernel aguardando reinício
	PhaseDone      Phase = "done"
)

// Progress é regravado periodicamente (troca atômica) enquanto a execução roda.
type Progress struct {
	Phase          Phase     `json:"phase"`
	FilesSeen      int64     `json:"files_seen"`
	FilesEligible  int64     `json:"files_eligible"`
	FilesProcessed int64     `json:"files_processed"`
	BytesEligible  int64     `json:"bytes_eligible"`
	BytesProcessed int64     `json:"bytes_processed"`
	Findings       int64     `json:"findings"`
	UpdatedAt      time.Time `json:"updated_at"`
	StartedAt      time.Time `json:"started_at"`
	// Throttle é o estado da limitação por pressão neste instante (nil sem limitação ativa).
	Throttle *ThrottleState `json:"throttle,omitempty"`
}

// Estados da limitação por pressão.
const (
	ThrottleReduced = "reduced" // paralelismo reduzido
	ThrottlePaused  = "paused"  // novos lotes suspensos até a pressão cair
)

// ThrottleState descreve a limitação em andamento.
type ThrottleState struct {
	State    string  `json:"state"`    // reduced ou paused
	Workers  int     `json:"workers"`  // workers liberados agora (0 quando pausada)
	Resource string  `json:"resource"` // cpu, io ou memory: o recurso que disparou
	Pressure float64 `json:"pressure"` // valor medido (avg10, %)
}

// Severity segue a escala do glossário.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// ValidSeverity aceita só os valores da escala; o resto vira médio no core.
func ValidSeverity(s Severity) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

// Category agrupa achados para a interface e para as regras de correlação.
type Category string

const (
	CategoryMalware     Category = "malware"
	CategoryWebshell    Category = "webshell"
	CategoryMiner       Category = "miner"
	CategorySuspicious  Category = "suspicious"
	CategoryIndicator   Category = "indicator"
	CategoryProcess     Category = "process"
	CategoryPersistence Category = "persistence"
	CategoryNetwork     Category = "network"
	CategoryTest        Category = "test" // controle positivo (EICAR, marcador): prova que o motor funciona
	// CategoryIntegrity: arquivo que não confere com o pacote instalado, ou pacote e repositório sem assinatura
	// conferível. O achado de arquivo é identificado pela localização, porque o conteúdo muda a cada alteração.
	CategoryIntegrity Category = "integrity"
	// CategoryUpdate: correção de segurança pendente, serviço com biblioteca antiga ou reinício pendente.
	CategoryUpdate Category = "update"
)

// Location identifica onde o objeto estava no momento da análise.
type Location struct {
	// Path é o caminho em UTF-8 com bytes inválidos substituídos; PathHex traz os bytes exatos quando diferem.
	Path    string    `json:"path"`
	PathHex string    `json:"path_hex,omitempty"`
	Dev     uint64    `json:"dev"`
	Ino     uint64    `json:"ino"`
	Size    int64     `json:"size"`
	Mode    uint32    `json:"mode"`
	UID     uint32    `json:"uid"`
	GID     uint32    `json:"gid"`
	Nlink   uint64    `json:"nlink"`
	Mtime   time.Time `json:"mtime"`
	Ctime   time.Time `json:"ctime"`
}

// SetPath preenche Path e, quando o nome não é UTF-8 válido, PathHex.
func (l *Location) SetPath(raw string) {
	if utf8.ValidString(raw) {
		l.Path = raw
		return
	}
	l.Path = string([]rune(raw)) // bytes inválidos viram U+FFFD
	l.PathHex = hex.EncodeToString([]byte(raw))
}

// RawPath devolve os bytes exatos do caminho.
func (l Location) RawPath() string {
	if l.PathHex != "" {
		if b, err := hex.DecodeString(l.PathHex); err == nil {
			return string(b)
		}
	}
	return l.Path
}

// Finding é uma linha de findings.ndjson.
type Finding struct {
	Engine        string            `json:"engine"`         // clamav, yara-x, lmd, inventory, inspector
	EngineVersion string            `json:"engine_version"` // versão do motor
	RulesVersion  string            `json:"rules_version"`  // versão das assinaturas ou do conjunto de regras
	Signature     string            `json:"signature"`      // nome da assinatura ou regra
	Source        string            `json:"source"`         // fonte da assinatura (ex.: vigiahost, clamav-main, rfxn)
	License       string            `json:"license,omitempty"`
	Author        string            `json:"author,omitempty"`
	Reference     string            `json:"reference,omitempty"`
	Description   string            `json:"description,omitempty"`
	Category      Category          `json:"category"`
	Severity      Severity          `json:"severity"`
	SHA256        string            `json:"sha256,omitempty"`
	FileType      string            `json:"file_type,omitempty"`
	Location      *Location         `json:"location,omitempty"`
	Process       *ProcessEvidence  `json:"process,omitempty"`
	Persistence   *PersistenceEntry `json:"persistence,omitempty"`
	// Subject identifica achados do sistema sem arquivo, processo ou item de persistência (pacote, repositório,
	// porta, serviço, kernel) e entra na identidade do achado.
	Subject    string            `json:"subject,omitempty"`
	Evidence   map[string]string `json:"evidence,omitempty"`
	DetectedAt time.Time         `json:"detected_at"`
}

// ProcessEvidence é o instantâneo do processo que gerou o achado (segredos mascarados).
type ProcessEvidence struct {
	PID       int      `json:"pid"`
	PPID      int      `json:"ppid"`
	UID       uint32   `json:"uid"`
	Comm      string   `json:"comm"`
	Exe       string   `json:"exe"`
	Cmdline   []string `json:"cmdline,omitempty"`
	Unit      string   `json:"unit,omitempty"`
	Cgroup    string   `json:"cgroup,omitempty"`
	ExeSHA256 string   `json:"exe_sha256,omitempty"`
	StartTime string   `json:"start_time,omitempty"`
	Listening []string `json:"listening,omitempty"`
	Connected []string `json:"connected,omitempty"`
}

// PersistenceEntry é um item do inventário de persistência (unidade, cron, chave SSH, preload...).
type PersistenceEntry struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	Detail  string `json:"detail,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Owner   string `json:"owner,omitempty"`
	Package string `json:"package,omitempty"`
	Change  string `json:"change,omitempty"` // added, changed, removed (em relação à execução anterior)
}

// Status é o estado final da execução (primeira das três dimensões do ADR-008).
type Status string

const (
	StatusCompleted   Status = "completed"
	StatusPartial     Status = "partial"
	StatusFailed      Status = "failed"
	StatusEngineError Status = "engine_failure"
	StatusCanceled    Status = "canceled"
	StatusInterrupted Status = "interrupted"
)

// SkipReason explica por que um arquivo elegível não foi analisado por um motor.
type SkipReason string

const (
	SkipExcluded   SkipReason = "excluded"
	SkipTooLarge   SkipReason = "too_large"
	SkipPermission SkipReason = "permission"
	SkipNotRegular SkipReason = "not_regular"
	SkipChanged    SkipReason = "changed_during_read"
	SkipTimeout    SkipReason = "timeout"
	SkipEngine     SkipReason = "engine_error"
	SkipMountPoint SkipReason = "other_filesystem"
	SkipCached     SkipReason = "cached" // já analisado com as mesmas versões; conta como analisado pelo cache
)

// EngineCoverage é a cobertura de um motor na execução.
type EngineCoverage struct {
	Engine        string               `json:"engine"`
	Version       string               `json:"version"`
	RulesVersion  string               `json:"rules_version"`
	Available     bool                 `json:"available"`
	SelfTest      SelfTest             `json:"selftest"`
	Eligible      int64                `json:"eligible"`
	Analyzed      int64                `json:"analyzed"`
	FromCache     int64                `json:"from_cache"`
	Skipped       map[SkipReason]int64 `json:"skipped,omitempty"`
	BytesAnalyzed int64                `json:"bytes_analyzed"`
	Seconds       float64              `json:"seconds"`
	Error         string               `json:"error,omitempty"`
	// Errors traz até 10 mensagens distintas de falha por arquivo, com a contagem de cada uma.
	Errors map[string]int64 `json:"errors,omitempty"`
}

// SelfTest é o resultado do autoteste com controles positivo e negativo (escopo, seção 7.4).
type SelfTest struct {
	Ran      bool   `json:"ran"`
	Positive bool   `json:"positive"`
	Negative bool   `json:"negative"`
	Detail   string `json:"detail,omitempty"`
}

// Passed indica controle positivo detectado e negativo limpo.
func (s SelfTest) Passed() bool { return s.Ran && s.Positive && s.Negative }

// Summary é gravado no fim da execução.
type Summary struct {
	RunID      string           `json:"run_id"`
	Kind       Kind             `json:"kind"`
	Status     Status           `json:"status"`
	Error      string           `json:"error,omitempty"`
	StartedAt  time.Time        `json:"started_at"`
	FinishedAt time.Time        `json:"finished_at"`
	Engines    []EngineCoverage `json:"engines"`
	// Inventory: totais do percurso.
	FilesSeen      int64                `json:"files_seen"`
	FilesEligible  int64                `json:"files_eligible"`
	BytesEligible  int64                `json:"bytes_eligible"`
	Skipped        map[SkipReason]int64 `json:"skipped,omitempty"`
	Findings       int64                `json:"findings"`
	Objects        int64                `json:"objects"`
	CacheHits      int64                `json:"cache_hits"`
	FilesPerSecond float64              `json:"files_per_second"`
	MBPerSecond    float64              `json:"mb_per_second"`
	Warnings       []string             `json:"warnings,omitempty"`
	// Metrics são as medidas de desempenho da execução (escopo, seção 12.1, "Medição").
	Metrics *Metrics `json:"metrics,omitempty"`
}

// Metrics são as medidas de desempenho gravadas pela própria execução no fim.
type Metrics struct {
	// Phases traz a duração de cada etapa, na ordem em que aconteceram.
	Phases []PhaseTiming `json:"phases"`
	// CPUSeconds é a CPU consumida pela unidade inteira (usuário + sistema, todos os processos filhos).
	CPUSeconds float64 `json:"cpu_seconds"`
	// MemoryPeakBytes é o pico de memória da unidade (cgroup; inclui o cache de páginas contido por MemoryHigh).
	MemoryPeakBytes int64 `json:"memory_peak_bytes"`
	// BytesRead é o volume lido para hash e análise (arquivos inalterados do cache não são relidos).
	BytesRead int64 `json:"bytes_read"`
	// Source diz de onde vieram CPU e memória: "cgroup" (unidade inteira) ou "rusage" (só o processo, sem cgroup v2).
	Source   string        `json:"source"`
	Throttle ThrottleStats `json:"throttle"`
}

// PhaseTiming é a duração de uma etapa.
type PhaseTiming struct {
	Phase   Phase   `json:"phase"`
	Seconds float64 `json:"seconds"`
}

// ThrottleStats resume a limitação por pressão ao longo da execução.
type ThrottleStats struct {
	// Available indica PSI legível no servidor; Enabled, que o perfil tinha algum limiar ligado.
	Available bool `json:"available"`
	Enabled   bool `json:"enabled"`
	// LimitedSeconds é o tempo com paralelismo reduzido ou pausado; PausedSeconds, só o tempo pausado.
	LimitedSeconds float64         `json:"limited_seconds"`
	PausedSeconds  float64         `json:"paused_seconds"`
	Events         []ThrottleEvent `json:"events,omitempty"`
	// EventsDropped conta eventos além do limite guardado (os primeiros ficam).
	EventsDropped int `json:"events_dropped,omitempty"`
}

// Ações registradas nos eventos de limitação.
const (
	ThrottleActionReduce  = "reduce"  // paralelismo reduzido
	ThrottleActionPause   = "pause"   // lotes suspensos
	ThrottleActionRaise   = "raise"   // paralelismo aumentado de novo, ainda abaixo do perfil
	ThrottleActionRestore = "restore" // de volta ao paralelismo do perfil
)

// ThrottleEvent é uma mudança de ritmo por pressão.
type ThrottleEvent struct {
	At        time.Time `json:"at"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Pressure  float64   `json:"pressure"`
	Threshold int       `json:"threshold"`
	Workers   int       `json:"workers"`
}
