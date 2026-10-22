package scan

import (
	"io"
	"log/slog"

	"github.com/guigallina27/vigiahost/internal/engines/clamav"
	"github.com/guigallina27/vigiahost/internal/engines/yarax"
	"github.com/guigallina27/vigiahost/internal/report"
)

// Nomes dos motores no relatório.
const (
	EngineYARA      = "yara-x"
	EngineClamAV    = "clamav"
	EngineInventory = "inventory"
)

// Config reúne o que a varredura precisa; o executor monta a partir do pedido e da descoberta dos motores.
type Config struct {
	Request report.Request
	OutDir  string
	Logger  *slog.Logger

	YARA         *yarax.Scanner // nil: YARA-X indisponível
	YARAVersion  string
	RulesVersion string

	Clamd        *clamav.Client // nil: sem clamd; usa Clamscan para tudo
	Clamscan     *clamav.Clamscan
	ClamVersion  clamav.VersionInfo
	ClamdMaxFile int64 // MaxFileSize do clamd; acima disso o arquivo vai para a fila de grandes (clamscan)

	CachePath string
	// BatchSize: arquivos por lote entregue ao yr; MaxLarge: tamanho da fila do clamscan antes de esvaziá-la.
	BatchSize int
	MaxLarge  int
	// YARAMaxFile: acima disso o YARA-X não analisa (motivo too_large).
	YARAMaxFile int64
	// LargeMaxFile: limite da fila de grandes do ClamAV.
	LargeMaxFile int64
}

func (c *Config) defaults() {
	if c.BatchSize <= 0 {
		c.BatchSize = 256
	}
	if c.MaxLarge <= 0 {
		c.MaxLarge = 512
		if c.Clamd == nil {
			c.MaxLarge = 8192 // sem clamd, tudo passa pelo clamscan: lotes maiores diluem a carga das assinaturas
		}
	}
	if c.YARAMaxFile <= 0 {
		c.YARAMaxFile = 1 << 30
	}
	if c.LargeMaxFile <= 0 {
		c.LargeMaxFile = 2 << 30
	}
	if c.ClamdMaxFile <= 0 {
		c.ClamdMaxFile = 25 << 20 // padrão do clamd
	}
	if c.Request.Profile.Workers <= 0 {
		c.Request.Profile.Workers = 2
	}
	if c.Request.Profile.ClamdConcurrency <= 0 {
		c.Request.Profile.ClamdConcurrency = 2
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
}
