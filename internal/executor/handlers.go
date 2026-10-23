package executor

import (
	"context"
	"encoding/json"
	"io/fs"
	"time"

	"github.com/guigallina27/vigiahost/internal/engines/clamav"
	"github.com/guigallina27/vigiahost/internal/ipc"
	"github.com/guigallina27/vigiahost/internal/scan"
	"github.com/guigallina27/vigiahost/internal/sysinfo"
)

// DefaultHandlers devolve as operações que não dependem do systemd. root é a raiz do sistema a inspecionar
// (os.DirFS("/")) e stateDir o diretório de estado do executor.
func DefaultHandlers(root fs.FS, stateDir string) map[ipc.Op]Handler {
	return map[ipc.Op]Handler{
		ipc.OpCapabilities: func(context.Context, json.RawMessage) (any, error) {
			return sysinfo.Detect(root), nil
		},
		// Saúde dos motores: só versões e o clamd respondendo. A compilação das regras acontece dentro da
		// execução, porque o YARA-X precisa de memória executável, vetada no serviço do executor.
		ipc.OpEngines: func(ctx context.Context, _ json.RawMessage) (any, error) {
			ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			return scan.DiscoverEngines(ctx, stateDir, scan.DiscoverOptions{}, func() (clamav.Config, bool) {
				return clamav.Discover(root)
			}), nil
		},
	}
}
