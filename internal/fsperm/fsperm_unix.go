//go:build unix

// Package fsperm confere se arquivos de terceiros que o executor vai usar como root (scripts do LMD, fontes locais
// de regras) só podem ser alterados pelo root.
package fsperm

import (
	"io/fs"
	"syscall"
)

// RootOnly exige dono root, nenhuma escrita para outros e escrita do grupo só se o grupo for o root (o install.sh
// oficial do LMD deixa internals/ em 775 e os arquivos em 664, com grupo root).
func RootOnly(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	perm := info.Mode().Perm()
	return st.Uid == 0 && perm&0o002 == 0 && (perm&0o020 == 0 || st.Gid == 0)
}
