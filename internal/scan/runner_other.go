//go:build !linux

package scan

import (
	"context"
	"errors"

	"github.com/guigallina27/vigiahost/internal/report"
)

// Run só existe no Linux: o inventário usa openat, fstatat e memfd.
func Run(context.Context, Config) (report.Summary, error) {
	return report.Summary{}, errors.New("varredura disponível só no Linux")
}
