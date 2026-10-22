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
	// Instantâneos da inspeção de processos.
	ProcessesFile   = "processes.json"
	PersistenceFile = "persistence.json"
)

// Kind é o tipo de execução.
type Kind string

const (
	KindFiles     Kind = "files"     // varredura de arquivos com os motores
	KindProcesses Kind = "processes" // inspeção de processos, rede e persistência
)

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
}

// Phase é a etapa corrente da execução, mostrada no progresso.
type Phase string

const (
	PhaseSelfTest  Phase = "selftest"
	PhaseInventory Phase = "inventory"
	PhaseScanning  Phase = "scanning"
	PhaseLarge     Phase = "large_files"
	PhaseInspect   Phase = "inspect"
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
	Engine        string            `json:"engine"`         // clamav, yara-x, inventory, inspector
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
	Evidence      map[string]string `json:"evidence,omitempty"`
	DetectedAt    time.Time         `json:"detected_at"`
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
}
