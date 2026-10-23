package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/setup"
)

const setupUsage = `Uso: vigiahost setup <plan|apply|uninstall> [opções]

  plan       detecta o ambiente e mostra as alterações previstas (nada é alterado)
  apply      aplica o plano (idempotente), registra tudo em ` + setup.ManifestPath + `
  uninstall  desfaz o que o setup registrou; -purge apaga também os dados; -remove-package remove o pacote

Opções de plan e apply: -listen IP:porta, -tls-cert, -tls-key, -trust-proxy, -answers arquivo.json, -json
`

func runSetup(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, setupUsage)
		return 2
	}
	switch args[0] {
	case "plan", "apply":
		return setupPlanApply(args[0], args[1:])
	case "uninstall":
		return setupUninstall(args[1:])
	default:
		fmt.Fprint(os.Stderr, setupUsage)
		return 2
	}
}

func setupPlanApply(cmd string, args []string) int {
	fs := flag.NewFlagSet("setup "+cmd, flag.ContinueOnError)
	var o setup.Options
	answers := fs.String("answers", "", "arquivo JSON com as respostas (listen, tls_cert, tls_key, trust_proxy)")
	fs.StringVar(&o.Listen, "listen", "", "endereço e porta do painel (padrão "+setup.DefaultListen+", acesso pelo túnel SSH)")
	fs.StringVar(&o.TLSCert, "tls-cert", "", "certificado TLS próprio (PEM)")
	fs.StringVar(&o.TLSKey, "tls-key", "", "chave do certificado TLS (PEM)")
	fs.BoolVar(&o.TrustProxy, "trust-proxy", false, "o painel fica atrás de um proxy reverso no endereço local")
	asJSON := fs.Bool("json", false, "saída em JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *answers != "" {
		b, err := os.ReadFile(*answers) //nolint:gosec // G703: arquivo de respostas indicado pelo próprio root
		if err == nil {
			var a setup.Options
			if err = json.Unmarshal(b, &a); err == nil {
				o = mergeOptions(a, o, fs)
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "arquivo de respostas:", err)
			return 2
		}
	}
	if cmd == "apply" && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "erro: o setup apply precisa ser executado como root")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sys := setup.Host()
	prev, err := sys.LoadManifest()
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		return 1
	}
	// Sem opções novas, a reexecução mantém as do apply anterior.
	if fs.NFlag() == 0 && *answers == "" && prev != nil {
		o = prev.Options
	}
	plan := sys.MakePlan(sys.Detect(ctx, listenOrDefault(o.Listen)), o, prev)
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(plan)
	} else {
		plan.Render(os.Stdout)
	}
	if cmd == "plan" {
		if len(plan.Blockers) > 0 {
			return 1
		}
		if plan.Pending() && !*asJSON {
			fmt.Printf("\nPara aplicar: sudo vigiahost setup apply%s\n", flagsEcho(o))
		}
		return 0
	}
	if len(plan.Blockers) > 0 {
		fmt.Fprintln(os.Stderr, "\nnada foi alterado: resolva os impedimentos acima")
		return 1
	}
	fmt.Println("\nAplicando")
	if _, err := sys.Apply(ctx, plan, prev, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		fmt.Fprintln(os.Stderr, "o que foi feito até aqui está no manifesto; rode o apply de novo depois de corrigir")
		return 1
	}
	afterApply(ctx, plan.Options)
	return 0
}

// mergeOptions usa o arquivo de respostas e deixa as opções passadas na linha de comando prevalecerem.
func mergeOptions(file, cli setup.Options, fs *flag.FlagSet) setup.Options {
	out := file
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "listen":
			out.Listen = cli.Listen
		case "tls-cert":
			out.TLSCert = cli.TLSCert
		case "tls-key":
			out.TLSKey = cli.TLSKey
		case "trust-proxy":
			out.TrustProxy = cli.TrustProxy
		}
	})
	return out
}

func listenOrDefault(l string) string {
	if l == "" {
		return setup.DefaultListen
	}
	return l
}

func flagsEcho(o setup.Options) string {
	var b strings.Builder
	if o.Listen != "" && o.Listen != setup.DefaultListen {
		b.WriteString(" -listen " + o.Listen)
	}
	if o.TLSCert != "" {
		b.WriteString(" -tls-cert " + o.TLSCert + " -tls-key " + o.TLSKey)
	}
	if o.TrustProxy {
		b.WriteString(" -trust-proxy")
	}
	return b.String()
}

// afterApply espera o painel responder e mostra como entrar (token de primeiro acesso e impressão digital do TLS).
func afterApply(ctx context.Context, o setup.Options) {
	listen := listenOrDefault(o.Listen)
	_, port, _ := net.SplitHostPort(listen)
	local := isLoopbackListen(listen)
	scheme := "http"
	if !local || o.TLSCert != "" {
		scheme = "https"
	}
	url := scheme + "://" + strings.Replace(listen, "0.0.0.0", "127.0.0.1", 1) + "/api/v1/health"
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		// Só para saber se o próprio painel subiu; o certificado pode ser o autoassinado recém-gerado.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // conferência local
	}}
	ok := false
	for i := 0; i < 30 && ctx.Err() == nil; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if resp, err := client.Do(req); err == nil { //nolint:gosec // endereço do próprio painel
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			ok = true
			break
		}
		time.Sleep(time.Second)
	}
	fmt.Println()
	if !ok {
		fmt.Println("O painel ainda não respondeu. Confira: systemctl status vigiahost-core vigiahost-executor")
		return
	}
	fmt.Printf("Painel no ar em %s://%s\n", scheme, listen)
	if fp, err := os.ReadFile(filepath.Join(filepath.Dir(defaultDB()), "tls", "fingerprint")); err == nil && o.TLSCert == "" && scheme == "https" {
		fmt.Printf("Certificado autoassinado, impressão digital SHA-256: %s\n", strings.TrimSpace(string(fp)))
	}
	if local {
		fmt.Printf("Acesse pelo túnel: ssh -L %s:127.0.0.1:%s root@servidor e abra http://127.0.0.1:%s\n", port, port, port)
	}
	if tok, err := os.ReadFile(filepath.Join(filepath.Dir(defaultDB()), firstAccessFileName)); err == nil {
		fmt.Println()
		printFirstAccess(strings.TrimSpace(string(tok)))
	}
}

func setupUninstall(args []string) int {
	fs := flag.NewFlagSet("setup uninstall", flag.ContinueOnError)
	purge := fs.Bool("purge", false, "apaga também os dados (banco, histórico, achados, cache e configuração)")
	removePkg := fs.Bool("remove-package", false, "remove o pacote vigiahost no fim (dnf/yum ou apt)")
	yes := fs.Bool("yes", false, "não pede confirmação")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "erro: a desinstalação precisa ser executada como root")
		return 1
	}
	what := "parar os serviços e desfazer as alterações registradas pelo setup (os dados ficam)"
	if *purge {
		what = "parar os serviços, desfazer as alterações do setup e APAGAR os dados em " + strings.Join(setup.DataDirs, ", ")
	}
	if !*yes && !confirm("Isto vai "+what+". Continuar? [s/N] ") {
		fmt.Println("nada foi alterado")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := setup.Host().Uninstall(ctx, *purge, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		return 1
	}
	if *removePkg {
		name, args := packageRemoval()
		if name == "" {
			fmt.Fprintln(os.Stderr, "gerenciador de pacotes não encontrado; remova o pacote vigiahost manualmente")
			return 1
		}
		cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // comando fixo do gerenciador de pacotes
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "remoção do pacote:", err)
			return 1
		}
	} else {
		fmt.Println("Para remover o pacote: dnf remove vigiahost (EL) ou apt remove vigiahost (Debian/Ubuntu)")
	}
	return 0
}

func packageRemoval() (string, []string) {
	for _, pm := range []struct {
		bin  string
		args []string
	}{{"dnf", []string{"-y", "remove", "vigiahost"}}, {"yum", []string{"-y", "remove", "vigiahost"}},
		{"apt-get", []string{"-y", "remove", "vigiahost"}}} {
		if p, err := exec.LookPath(pm.bin); err == nil {
			return p, pm.args
		}
	}
	return "", nil
}

func confirm(prompt string) bool {
	fmt.Print(prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "s", "sim", "y", "yes":
		return true
	}
	return false
}
