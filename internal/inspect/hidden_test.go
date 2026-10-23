package inspect

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/guigallina27/vigiahost/internal/report"
)

// fakeSystem simula listagens que mudam a cada rodada (processos e conexões efêmeros).
type fakeSystem struct {
	mu     sync.Mutex
	round  int
	listed []map[int]bool // listagem por rodada (a última vale para as seguintes)
	alive  []map[int]bool // PIDs que respondem por rodada
	ports  []map[PortKey]bool
	nl     []map[PortKey]bool
	inUse  []map[PortKey]bool
}

func at[T any](list []T, i int) T {
	if i >= len(list) {
		return list[len(list)-1]
	}
	return list[i]
}

func (f *fakeSystem) probes() hiddenProbes {
	return hiddenProbes{
		pidMax: 5000,
		listPIDs: func() (map[int]bool, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return at(f.listed, f.round), nil
		},
		pidExists: func(pid int) []string {
			f.mu.Lock()
			defer f.mu.Unlock()
			if at(f.alive, f.round)[pid] {
				return []string{"kill", "getsid"}
			}
			return nil
		},
		procInfo: func(pid int) (string, string, bool) { return "kworkerx", "/usr/lib/.x/k", true },
		listPorts: func() (map[PortKey]bool, map[PortKey]bool, bool, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return at(f.ports, f.round), at(f.nl, f.round), true, nil
		},
		portInUse: func(k PortKey) (bool, bool) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if k.Port < 1024 && k.Proto == "udp" {
				return false, false // sem permissão: não conta como testada
			}
			return at(f.inUse, f.round)[k], true
		},
		wait: func(context.Context) {
			f.mu.Lock()
			f.round++
			f.mu.Unlock()
		},
		workers: 3,
	}
}

func TestHiddenProcessesConfirmedTwice(t *testing.T) {
	f := &fakeSystem{
		listed: []map[int]bool{{1: true, 100: true}, {1: true, 100: true, 200: true}},
		// 200: processo novo entre a listagem e o teste (aparece na 2ª listagem); 300: morreu antes da confirmação;
		// 4242: oculto em todas as rodadas.
		alive: []map[int]bool{{1: true, 100: true, 200: true, 300: true, 4242: true}, {1: true, 100: true, 200: true, 4242: true}},
	}
	res := findHiddenProcesses(context.Background(), f.probes())
	if !res.Checked || res.Visible != 2 || res.Discarded != 2 {
		t.Fatalf("%+v", res)
	}
	if len(res.Found) != 1 || res.Found[0].PID != 4242 || !res.Found[0].DirectAccess || !slices.Equal(res.Found[0].Checks, []string{"getsid", "kill"}) {
		t.Fatalf("oculto: %+v", res.Found)
	}
	if f.round != Confirmations {
		t.Fatalf("esperava %d conferências, foram %d", Confirmations, f.round)
	}
}

func TestHiddenProcessesNothingHiddenSkipsWait(t *testing.T) {
	f := &fakeSystem{listed: []map[int]bool{{1: true}}, alive: []map[int]bool{{1: true}}}
	res := findHiddenProcesses(context.Background(), f.probes())
	if len(res.Found) != 0 || f.round != 0 {
		t.Fatalf("sem candidatos não espera: %+v, rodadas %d", res, f.round)
	}
}

func TestHiddenPorts(t *testing.T) {
	ssh := PortKey{"tcp", 22}
	back := PortKey{"tcp", 31337}
	eph := PortKey{"tcp", 45000}
	filt := PortKey{"tcp", 8443}
	f := &fakeSystem{
		ports: []map[PortKey]bool{{ssh: true}, {ssh: true, eph: true}},
		nl:    []map[PortKey]bool{{ssh: true, filt: true}},
		// 45000: conexão de saída aberta entre a listagem e o bind (aparece na listagem seguinte).
		inUse: []map[PortKey]bool{{back: true, eph: true, {"udp", 53}: true}},
	}
	res := findHiddenPorts(context.Background(), f.probes())
	if !res.Checked || res.Discarded != 1 || res.Skipped != 1023 {
		t.Fatalf("%+v", res)
	}
	if len(res.Found) != 2 {
		t.Fatalf("portas: %+v", res.Found)
	}
	if res.Found[0] != (HiddenPort{PortKey: filt, Reason: PortNetlinkOnly}) || res.Found[1] != (HiddenPort{PortKey: back, Reason: PortBindOnly}) {
		t.Fatalf("portas: %+v", res.Found)
	}
	// O bind nunca toca porta listada.
	if res.Probed != 2*65535-2-1023 {
		t.Fatalf("testadas: %d", res.Probed)
	}
}

func TestHiddenFindings(t *testing.T) {
	rep := HiddenReport{
		Processes: HiddenProcesses{Found: []HiddenProcess{{PID: 4242, Checks: []string{"kill"}, Comm: "x"}}},
		Ports: HiddenPorts{Found: []HiddenPort{{PortKey{"tcp", 31337}, PortBindOnly}, {PortKey{"udp", 4789}, PortBindOnly},
			{PortKey{"tcp", 8443}, PortNetlinkOnly}}},
	}
	got := HiddenFindings(rep)
	if len(got) != 4 {
		t.Fatalf("%+v", got)
	}
	if got[0].Signature != "processo.oculto" || got[0].Severity != report.SeverityCritical || got[0].Process.PID != 4242 || got[0].Subject != "pid:4242" {
		t.Fatalf("processo: %+v", got[0])
	}
	if got[1].Severity != report.SeverityHigh || got[1].Subject != "tcp/31337" || got[1].Category != report.CategoryNetwork {
		t.Fatalf("tcp: %+v", got[1])
	}
	if got[2].Severity != report.SeverityMedium {
		t.Fatalf("udp é médio: %+v", got[2])
	}
	if got[3].Evidence["motivo"] != PortNetlinkOnly {
		t.Fatalf("netlink: %+v", got[3])
	}
}

func TestAnalyzePackageMismatch(t *testing.T) {
	p := &Process{PID: 10, Comm: "sshd", Exe: "/usr/sbin/sshd", Package: "openssh-server", PackageStatus: "mismatch",
		packageEvidence: map[string]string{"pacote": "openssh-server-9.9p1-13.el9.x86_64"}}
	hits := AnalyzeProcesses([]*Process{p}, 1000)
	if len(hits) != 1 || hits[0].Signature != "processo.binario_de_pacote_alterado" || hits[0].Severity != report.SeverityCritical ||
		hits[0].Evidence["pacote"] == "" {
		t.Fatalf("%+v", hits)
	}
}
