//go:build !linux

package executor

import (
	"log/slog"

	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/profile"
)

// Runs só funciona no Linux (systemd por D-Bus); fora dele não registra operações.
type Runs struct {
	Logger   *slog.Logger
	StateDir string
	Exe      string
	CoreGID  int
	Local    LocalConfig
	Hardware profile.Hardware
	// UserRules é o diretório das fontes locais de regras.
	UserRules string
}

func (r *Runs) Prepare() error              { return nil }
func (r *Runs) Close()                      {}
func (r *Runs) Register(map[ipc.Op]Handler) {}
