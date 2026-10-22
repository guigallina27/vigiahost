package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/guigallina27/vigiahost/internal/core"
	"github.com/guigallina27/vigiahost/internal/sysinfo"
	"github.com/guigallina27/vigiahost/internal/version"
)

func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	socket := fs.String("executor-socket", defaultExecutorSocket, "socket do executor")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	caps := sysinfo.Detect(os.DirFS("/"))
	fmt.Printf("VigiaHost %s\n\n", version.Version)
	fmt.Printf("Sistema        %s (%s %s, família %s)\n", orDash(caps.DistroName), orDash(caps.DistroID), orDash(caps.DistroVersion), orDash(caps.Family()))
	fmt.Printf("Kernel         %s (%s)\n", orDash(caps.Kernel), caps.Arch)
	fmt.Printf("systemd        %s\n", yesNo(caps.Systemd, "em execução", "ausente: execuções isoladas e limites indisponíveis"))
	fmt.Printf("cgroup v2      %s\n", yesNo(caps.CgroupV2, "sim", "não: pausa universal e limite de I/O indisponíveis"))
	fmt.Printf("PSI            %s\n", yesNo(caps.PSI, "sim", "não: limitação adaptativa de carga indisponível"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st := core.ProbeExecutor(*socket, localHello())(ctx)
	switch {
	case st.Connected && st.Error == "":
		fmt.Printf("Executor       conectado, versão %s, protocolo %s\n", st.Version, st.Protocol)
		return 0
	case st.Connected:
		fmt.Printf("Executor       conectado, mas a consulta falhou: %s\n", st.Error)
		return 1
	default:
		fmt.Printf("Executor       indisponível: %s\n", st.Error)
		if hint := executorHint(*socket); hint != "" {
			fmt.Printf("               %s\n", hint)
		}
		return 1
	}
}

func executorHint(socket string) string {
	if _, err := os.Stat(socket); errors.Is(err, os.ErrNotExist) {
		return "verifique: systemctl status vigiahost-executor"
	}
	if os.Geteuid() != 0 {
		return "execute como root ou como o usuário vigiahost"
	}
	return ""
}

func yesNo(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
