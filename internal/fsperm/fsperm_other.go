//go:build !unix

// Package fsperm confere se arquivos de terceiros que o executor vai usar como root (scripts do LMD, fontes locais
// de regras) só podem ser alterados pelo root.
package fsperm

import "io/fs"

// RootOnly fora do Unix (testes no Windows): o executor só roda no Linux, onde vale a conferência de verdade.
func RootOnly(fs.FileInfo) bool { return true }
