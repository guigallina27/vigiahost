//go:build unix

package main

import (
	"os"
	"syscall"
)

// copyOwner entrega os arquivos ao mesmo dono e grupo de ref (o banco do serviço), depois de gravados pelo root.
func copyOwner(ref string, paths ...string) {
	info, err := os.Stat(ref) //nolint:gosec // G703: diretório de estado do próprio serviço
	if err != nil {
		return
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	for _, p := range paths {
		_ = os.Lchown(p, int(st.Uid), int(st.Gid))
	}
}
