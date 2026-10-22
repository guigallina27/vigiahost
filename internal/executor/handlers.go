package executor

import (
	"context"
	"encoding/json"
	"io/fs"

	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/sysinfo"
)

// DefaultHandlers devolve as operações da Fase 0. root é a raiz do sistema a inspecionar (os.DirFS("/")).
func DefaultHandlers(root fs.FS) map[ipc.Op]Handler {
	return map[ipc.Op]Handler{
		ipc.OpCapabilities: func(context.Context, json.RawMessage) (any, error) {
			return sysinfo.Detect(root), nil
		},
	}
}
