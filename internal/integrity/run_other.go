//go:build !linux

package integrity

import (
	"context"
	"errors"
	"log/slog"

	"github.com/guigallina27/vigiahost/internal/pkgverify"
	"github.com/guigallina27/vigiahost/internal/report"
)

// Config da execução de integridade (só Linux).
type Config struct {
	Request  report.Request
	OutDir   string
	Logger   *slog.Logger
	Verifier *pkgverify.Verifier
}

// Run só existe no Linux.
func Run(context.Context, Config) (report.Summary, error) {
	return report.Summary{}, errors.New("a verificação de integridade só roda no Linux")
}
