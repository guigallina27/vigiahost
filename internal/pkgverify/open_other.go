//go:build !unix

package pkgverify

// openNoFollow não tem equivalente fora do Unix; o pacote só roda de verdade no Linux.
const openNoFollow = 0
