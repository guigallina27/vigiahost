package inspect

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/report"
	"github.com/guigallina27/vigiahost/internal/version"
)

// Busca por processos e portas ocultos (técnica do unhide, escopo, seção 7.5): um PID que responde a chamadas de
// sistema mas não aparece na listagem do /proc, ou uma porta em uso (bind recusado) que não aparece no /proc/net nem
// no netlink (sock_diag, o que o ss usa). Processos e conexões efêmeros nascem e morrem entre a listagem e o teste;
// por isso cada candidato é conferido mais duas vezes, com nova listagem, antes de virar achado.

// Confirmations é quantas conferências extras cada candidato precisa passar.
const Confirmations = 2

// HiddenProcess é um PID que existe para o kernel e não aparece na listagem.
type HiddenProcess struct {
	PID int `json:"pid"`
	// Checks são as chamadas que confirmaram o processo (kill, getpgid, getsid).
	Checks []string `json:"checks"`
	// DirectAccess: /proc/PID abre mesmo fora da listagem (o rootkit só filtra a leitura do diretório).
	DirectAccess bool   `json:"direct_access"`
	Comm         string `json:"comm,omitempty"`
	Exe          string `json:"exe,omitempty"`
}

// HiddenProcesses é o resultado da busca por processos ocultos.
type HiddenProcesses struct {
	Checked bool            `json:"checked"`
	PIDMax  int             `json:"pid_max"`
	Visible int             `json:"visible"`
	Found   []HiddenProcess `json:"found"`
	// Discarded conta candidatos que sumiram ou apareceram na listagem nas conferências (processos efêmeros).
	Discarded int    `json:"discarded"`
	Error     string `json:"error,omitempty"`
}

// PortKey identifica uma porta por protocolo (as duas famílias juntas: um socket [::] de pilha dupla ocupa a porta
// também no IPv4).
type PortKey struct {
	Proto string `json:"proto"`
	Port  int    `json:"port"`
}

// Motivos de porta oculta.
const (
	PortBindOnly    = "bind_only"    // em uso para o kernel, ausente do /proc/net e do netlink
	PortNetlinkOnly = "netlink_only" // o netlink mostra, o /proc/net esconde
	PortProcOnly    = "proc_only"    // o /proc/net mostra, o netlink esconde
)

// HiddenPort é uma porta em uso que alguma listagem esconde.
type HiddenPort struct {
	PortKey
	Reason string `json:"reason"`
}

// HiddenPorts é o resultado da busca por portas ocultas.
type HiddenPorts struct {
	Checked bool `json:"checked"`
	// Probed conta as portas testadas por bind (as que não estavam em nenhuma listagem); Skipped, as que o bind não
	// conseguiu testar (porta privilegiada sem permissão, família desligada).
	Probed    int          `json:"probed"`
	Skipped   int          `json:"skipped"`
	Listed    int          `json:"listed"`
	Netlink   bool         `json:"netlink"`
	Found     []HiddenPort `json:"found"`
	Discarded int          `json:"discarded"`
	Error     string       `json:"error,omitempty"`
}

// HiddenReport é o conteúdo de hidden.json.
type HiddenReport struct {
	Processes HiddenProcesses `json:"processes"`
	Ports     HiddenPorts     `json:"ports"`
	Seconds   float64         `json:"seconds"`
}

// hiddenProbes são as consultas ao sistema (falsas nos testes).
type hiddenProbes struct {
	pidMax    int
	listPIDs  func() (map[int]bool, error)
	pidExists func(pid int) []string
	procInfo  func(pid int) (comm, exe string, direct bool)
	// listPorts devolve as portas no /proc/net e no netlink (nlOK falso quando o netlink não respondeu).
	listPorts func() (proc, nl map[PortKey]bool, nlOK bool, err error)
	// portInUse testa a porta por bind: em uso, ou não testada (sem permissão, família indisponível).
	portInUse func(k PortKey) (inUse, probed bool)
	wait      func(ctx context.Context)
	workers   int
}

func defaultWait(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
	}
}

// findHiddenProcesses varre todos os PIDs possíveis e confirma os candidatos.
func findHiddenProcesses(ctx context.Context, p hiddenProbes) HiddenProcesses {
	res := HiddenProcesses{PIDMax: p.pidMax, Found: []HiddenProcess{}}
	visible, err := p.listPIDs()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Visible = len(visible)
	workers := max(p.workers, 1)
	found := make(chan map[int][]string, workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			m := map[int][]string{}
			for pid := 1 + w; pid <= p.pidMax && ctx.Err() == nil; pid += workers {
				if visible[pid] {
					continue
				}
				if checks := p.pidExists(pid); len(checks) > 0 {
					m[pid] = checks
				}
			}
			found <- m
		}(w)
	}
	cands := map[int][]string{}
	for w := 0; w < workers; w++ {
		for pid, c := range <-found {
			cands[pid] = c
		}
	}
	if ctx.Err() != nil {
		res.Error = "busca interrompida"
		return res
	}
	res.Checked = true
	for round := 0; round < Confirmations && len(cands) > 0; round++ {
		p.wait(ctx)
		again, err := p.listPIDs()
		if err != nil {
			res.Error = err.Error()
			return res
		}
		for pid, checks := range cands {
			now := p.pidExists(pid)
			if again[pid] || len(now) == 0 {
				delete(cands, pid)
				res.Discarded++
				continue
			}
			cands[pid] = mergeChecks(checks, now)
		}
	}
	for pid, checks := range cands {
		h := HiddenProcess{PID: pid, Checks: checks}
		if p.procInfo != nil {
			h.Comm, h.Exe, h.DirectAccess = p.procInfo(pid)
		}
		res.Found = append(res.Found, h)
	}
	sort.Slice(res.Found, func(i, j int) bool { return res.Found[i].PID < res.Found[j].PID })
	return res
}

func mergeChecks(a, b []string) []string {
	for _, x := range b {
		found := false
		for _, y := range a {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			a = append(a, x)
		}
	}
	sort.Strings(a)
	return a
}

// findHiddenPorts compara /proc/net, netlink e bind, e confirma os candidatos.
func findHiddenPorts(ctx context.Context, p hiddenProbes) HiddenPorts {
	res := HiddenPorts{Found: []HiddenPort{}}
	procSet, nlSet, nlOK, err := p.listPorts()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Netlink = nlOK
	listed := map[PortKey]bool{}
	for k := range procSet {
		listed[k] = true
	}
	for k := range nlSet {
		listed[k] = true
	}
	res.Listed = len(listed)
	cands := map[PortKey]string{}
	if nlOK {
		for k := range nlSet {
			if !procSet[k] {
				cands[k] = PortNetlinkOnly
			}
		}
		for k := range procSet {
			if !nlSet[k] {
				cands[k] = PortProcOnly
			}
		}
	}
	// Só as portas fora de qualquer listagem passam pelo bind: nenhum serviço conhecido é tocado.
	for _, proto := range []string{"tcp", "udp"} {
		for port := 1; port <= 65535 && ctx.Err() == nil; port++ {
			k := PortKey{Proto: proto, Port: port}
			if listed[k] {
				continue
			}
			inUse, probed := p.portInUse(k)
			if !probed {
				res.Skipped++
				continue
			}
			res.Probed++
			if inUse {
				cands[k] = PortBindOnly
			}
		}
	}
	if ctx.Err() != nil {
		res.Error = "busca interrompida"
		return res
	}
	res.Checked = true
	for round := 0; round < Confirmations && len(cands) > 0; round++ {
		p.wait(ctx)
		procSet, nlSet, nlOK, err = p.listPorts()
		if err != nil {
			res.Error = err.Error()
			return res
		}
		for k, reason := range cands {
			still := false
			switch reason {
			case PortBindOnly:
				if !procSet[k] && !nlSet[k] {
					inUse, probed := p.portInUse(k)
					still = inUse && probed
				}
			case PortNetlinkOnly:
				still = nlOK && nlSet[k] && !procSet[k]
			case PortProcOnly:
				still = nlOK && procSet[k] && !nlSet[k]
			}
			if !still {
				delete(cands, k)
				res.Discarded++
			}
		}
	}
	for k, reason := range cands {
		res.Found = append(res.Found, HiddenPort{PortKey: k, Reason: reason})
	}
	sort.Slice(res.Found, func(i, j int) bool {
		if res.Found[i].Proto != res.Found[j].Proto {
			return res.Found[i].Proto < res.Found[j].Proto
		}
		return res.Found[i].Port < res.Found[j].Port
	})
	return res
}

// HiddenFindings transforma o resultado em achados.
func HiddenFindings(rep HiddenReport) []report.Finding {
	var out []report.Finding
	for _, h := range rep.Processes.Found {
		ev := map[string]string{"confirmado_por": strings.Join(h.Checks, ", "),
			"conferencias": strconv.Itoa(Confirmations+1) + " de " + strconv.Itoa(Confirmations+1)}
		if h.DirectAccess {
			ev["acesso_direto"] = "/proc/" + strconv.Itoa(h.PID) + " abre, mas não aparece na listagem"
		} else {
			ev["acesso_direto"] = "/proc/" + strconv.Itoa(h.PID) + " inacessível"
		}
		out = append(out, report.Finding{Engine: Engine, EngineVersion: version.Version, Signature: "processo.oculto",
			Source: "vigiahost", Category: report.CategoryProcess, Severity: report.SeverityCritical,
			Description: "processo existe para o kernel mas não aparece na listagem do /proc (indício de rootkit)",
			Subject:     "pid:" + strconv.Itoa(h.PID),
			Process:     &report.ProcessEvidence{PID: h.PID, Comm: h.Comm, Exe: h.Exe}, Evidence: ev})
	}
	for _, h := range rep.Ports.Found {
		sev := report.SeverityHigh
		desc := ""
		switch h.Reason {
		case PortBindOnly:
			desc = fmt.Sprintf("porta %s %d em uso, mas ausente do /proc/net e do netlink (indício de rootkit)", h.Proto, h.Port)
			if h.Proto == "udp" {
				// Sockets UDP do próprio kernel (túneis, NFS) podem não ter dono visível: médio até a revisão.
				sev = report.SeverityMedium
			}
		case PortNetlinkOnly:
			desc = fmt.Sprintf("porta %s %d aparece no netlink e some do /proc/net (listagem filtrada)", h.Proto, h.Port)
		case PortProcOnly:
			desc = fmt.Sprintf("porta %s %d aparece no /proc/net e some do netlink (listagem filtrada)", h.Proto, h.Port)
		}
		out = append(out, report.Finding{Engine: Engine, EngineVersion: version.Version, Signature: "rede.porta_oculta",
			Source: "vigiahost", Category: report.CategoryNetwork, Severity: sev, Description: desc,
			Subject: h.Proto + "/" + strconv.Itoa(h.Port),
			Evidence: map[string]string{"protocolo": h.Proto, "porta": strconv.Itoa(h.Port), "motivo": h.Reason,
				"conferencias": strconv.Itoa(Confirmations+1) + " de " + strconv.Itoa(Confirmations+1)}})
	}
	return out
}
