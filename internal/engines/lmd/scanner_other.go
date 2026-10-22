//go:build !linux

package lmd

import (
	"context"
	"errors"
	"os"
)

// ScanFiles só existe no Linux (depende de /proc/<pid>/fd e de grupos de processos).
func (s *Scanner) ScanFiles(context.Context, []*os.File) (Result, error) {
	return Result{}, errors.New("o LMD só roda no Linux")
}
