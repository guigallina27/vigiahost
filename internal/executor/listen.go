package executor

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"os"
	"runtime"
)

// ListenUnix cria o socket do executor com permissão 0660 e dono root:gid. Um socket antigo no mesmo
// caminho é removido; qualquer outro tipo de arquivo no caminho é tratado como erro.
func ListenUnix(ctx context.Context, path string, gid int) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("%s existe e não é um socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	// O socket nasce com a umask restritiva do serviço (0077); só então é aberto ao grupo do core.
	if runtime.GOOS == "linux" && gid >= 0 {
		if err := os.Chown(path, 0, gid); err != nil {
			ln.Close()
			return nil, err
		}
	}
	//nolint:gosec // G302: o socket precisa ser acessível ao grupo do core; a política do executor confere o UID.
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
