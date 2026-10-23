//go:build linux

// Comando memfdrun monta, só no laboratório, os dois cenários de "executável sem arquivo" que a análise de processos
// (escopo, fase 2) precisa reconhecer, usando uma cópia do /usr/bin/sleep com o marcador inerte do controle positivo
// anexado ao fim (o ELF ignora bytes depois das seções, então o programa roda normalmente):
//
//	memfdrun memfd   SEGUNDOS   executa a cópia a partir de um memfd (/proc/PID/exe aponta para "/memfd:... (deleted)")
//	memfdrun apagado SEGUNDOS   executa a cópia a partir de um arquivo já removido do disco ("... (deleted)")
//
// Nos dois casos o processo final é só um sleep: nada de rede, nada de escrita. Use por test/lab/scenario-memfd.sh.
package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/guigallina27/vigiahost/internal/controls"
)

const memfdName = "vigiahost-controle"

func main() {
	if len(os.Args) != 3 {
		fail(fmt.Errorf("uso: memfdrun memfd|apagado SEGUNDOS"))
	}
	if _, err := strconv.ParseUint(os.Args[2], 10, 32); err != nil {
		fail(fmt.Errorf("duração inválida: %q", os.Args[2]))
	}
	payload, err := os.ReadFile("/usr/bin/sleep")
	if err != nil {
		fail(err)
	}
	payload = append(payload, "\n"+controls.Marker+"\n"...)

	var fd int
	switch os.Args[1] {
	case "memfd":
		fd, err = fromMemfd(payload)
	case "apagado":
		fd, err = fromDeletedFile(payload)
	default:
		err = fmt.Errorf("cenário desconhecido: %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
	// O descritor só de leitura não tem O_CLOEXEC: precisa existir até o execve terminar de carregar o programa.
	fail(syscall.Exec(fmt.Sprintf("/proc/self/fd/%d", fd), []string{"sleep", os.Args[2]}, []string{}))
}

// fromMemfd grava o programa num memfd e devolve um descritor só de leitura para ele. O descritor gravável é fechado
// antes do execve, que recusa (ETXTBSY) arquivos ainda abertos para escrita.
func fromMemfd(payload []byte) (int, error) {
	r, err := unix.MemfdCreate(memfdName, 0)
	if err != nil {
		return -1, fmt.Errorf("memfd_create: %w", err)
	}
	w := os.NewFile(uintptr(r), memfdName)
	if _, err := w.Write(payload); err != nil {
		return -1, err
	}
	ro, err := syscall.Open(fmt.Sprintf("/proc/self/fd/%d", w.Fd()), syscall.O_RDONLY, 0)
	if err != nil {
		return -1, err
	}
	return ro, w.Close()
}

// fromDeletedFile grava o programa em /var/tmp, abre só para leitura e remove o nome: o processo roda de um arquivo
// que não existe mais no disco.
func fromDeletedFile(payload []byte) (int, error) {
	f, err := os.CreateTemp("/var/tmp", "vigiahost-controle-apagado-")
	if err != nil {
		return -1, err
	}
	path := f.Name()
	defer func() { _ = os.Remove(path) }()
	if _, err := f.Write(payload); err != nil {
		_ = f.Close()
		return -1, err
	}
	// CreateTemp cria com 0600; sem o bit de execução o execve recusa (EACCES).
	if err := f.Chmod(0o700); err != nil {
		_ = f.Close()
		return -1, err
	}
	if err := f.Close(); err != nil {
		return -1, err
	}
	ro, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		return -1, err
	}
	return ro, os.Remove(path)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "memfdrun:", err)
	os.Exit(1)
}
