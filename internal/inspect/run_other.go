//go:build !linux

package inspect

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/scan"
)

// Arquivos extras gravados no diretório da execução de processos.
const (
	ProcessesFile   = "processes.json"
	PersistenceFile = "persistence.json"
)

// Config da inspeção (só Linux).
type Config struct {
	Request   report.Request
	OutDir    string
	StateDir  string
	Logger    *slog.Logger
	Engines   scan.Config
	Proc      string
	Root      fs.FS
	CPUSample time.Duration
}

// PersistenceReport é o conteúdo de persistence.json.
type PersistenceReport struct {
	Baseline bool                      `json:"baseline"`
	Items    []report.PersistenceEntry `json:"items"`
	Removed  []report.PersistenceEntry `json:"removed,omitempty"`
}

// Run só existe no Linux.
func Run(context.Context, Config) (report.Summary, error) {
	return report.Summary{}, errors.New("a inspeção de processos só roda no Linux")
}
