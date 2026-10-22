//go:build !linux

package main

import "errors"

// A árvore sintética usa FIFO, links simbólicos e físicos e permissões do Linux; gere-a no laboratório.
func runSynthetic([]string) error {
	return errors.New("o corpus sintético só é gerado em Linux (laboratório)")
}

// A conferência entrega os arquivos aos motores por /dev/fd, recurso do Linux.
func runVerify([]string) error {
	return errors.New("a conferência do corpus só roda em Linux (laboratório)")
}

// A sobreposição com o LMD usa /proc/<pid>/fd e o maldet instalado, só no laboratório.
func runOverlap([]string) error {
	return errors.New("a sobreposição com o LMD só roda em Linux (laboratório)")
}
