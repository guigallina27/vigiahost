//go:build !unix

package clamav

// Fora do Unix não há passagem de descritor; o envio falha e o arquivo fica sem análise do clamd.
func unixRights(int) []byte { return nil }
