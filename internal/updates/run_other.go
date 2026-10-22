//go:build !linux

package updates

import (
	"context"
	"errors"
	"log/slog"

	"github.com/guigallina27/vigiahost/internal/report"
)

// Config da execução de atualizações (só Linux).
type Config struct {
	Request report.Request
	OutDir  string
	Logger  *slog.Logger
	Refresh bool
}

// Run só existe no Linux.
func Run(context.Context, Config) (report.Summary, error) {
	return report.Summary{}, errors.New("a conferência de atualizações só roda no Linux")
}
