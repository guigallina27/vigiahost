package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/core"
	"github.com/guigallina27/vigiahost/internal/setup"
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

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Diagnóstico sanitizado: só estados e versões, nunca tokens, senhas ou conteúdo de arquivos.
	sys := setup.Host()
	env := sys.Detect(ctx, "")
	eng := env.Engines
	switch {
	case eng.YR != "":
		fmt.Printf("YARA-X         %s %s%s\n", eng.YR, eng.YRVersion, suffix(eng.YRError))
	default:
		fmt.Printf("YARA-X         ausente: instale o binário oficial \"yr\" (veja vigiahost setup plan)\n")
	}
	switch {
	case eng.Clamd != nil:
		fmt.Printf("ClamAV         clamd em %s, %s, assinaturas %s\n", eng.Clamd.LocalSocket, orDash(eng.ClamVersion.Engine), orDash(eng.ClamVersion.Database))
	case eng.Clamscan != "":
		fmt.Printf("ClamAV         só clamscan (%s); clamd: %s\n", eng.Clamscan, eng.ClamdError)
	default:
		fmt.Printf("ClamAV         ausente\n")
	}
	for _, u := range setup.Units {
		st := env.Services[u]
		fmt.Printf("%-14s %s, %s\n", strings.TrimSuffix(u, ".service"), st.Enabled, st.Active)
	}
	fmt.Printf("Painéis        %s\n", orDash(strings.Join(env.Panels, ", ")))
	if len(env.OtherAV) > 0 {
		fmt.Printf("Outros agentes %s\n", strings.Join(env.OtherAV, ", "))
	}
	if env.SELinux != "" {
		fmt.Printf("SELinux        %s\n", env.SELinux)
	}
	if m, err := sys.LoadManifest(); err == nil && m != nil {
		fmt.Printf("Setup          aplicado em %s (escuta %s)\n", m.UpdatedAt.Local().Format("02/01/2006 15:04"), orDash(m.Options.Listen))
	} else {
		fmt.Printf("Setup          não aplicado: rode sudo vigiahost setup plan\n")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(defaultDB()), firstAccessFileName)); err == nil {
		fmt.Printf("Primeiro acesso pendente: sudo vigiahost first-access\n")
	}

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

func suffix(err string) string {
	if err == "" {
		return ""
	}
	return " (" + err + ")"
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
