// Comando vigiahost: serviço web (serve), diagnóstico (doctor) e versão.
package main

import (
	"fmt"
	"os"

	"github.com/guigallina27/vigiahost/internal/version"
)

const usage = `Uso: vigiahost <comando> [opções]

Comandos:
  serve     inicia o serviço web e a API (normalmente pelo systemd)
  doctor    verifica o sistema e a conexão com o executor
  version   mostra a versão

Use "vigiahost <comando> -h" para ver as opções de cada comando.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		os.Exit(runServe(os.Args[2:]))
	case "doctor":
		os.Exit(runDoctor(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Printf("vigiahost %s (commit %s, %s), protocolo %d.%d\n",
			version.Version, version.Commit, version.Date, version.ProtocolMajor, version.ProtocolMinor)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "comando desconhecido: %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}
