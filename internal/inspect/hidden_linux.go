package inspect

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// linuxHiddenProbes consulta o sistema em execução (procfs em proc).
func linuxHiddenProbes(proc string) hiddenProbes {
	return hiddenProbes{
		pidMax:    readPIDMax(proc),
		listPIDs:  func() (map[int]bool, error) { return listAllPIDs(proc) },
		pidExists: pidExists,
		procInfo: func(pid int) (string, string, bool) {
			dir := filepath.Join(proc, strconv.Itoa(pid))
			if _, err := os.Stat(dir); err != nil {
				return "", "", false
			}
			comm, _ := os.ReadFile(filepath.Join(dir, "comm")) //nolint:gosec // procfs
			exe, _ := os.Readlink(filepath.Join(dir, "exe"))
			return strings.TrimSpace(string(comm)), exe, true
		},
		listPorts: func() (map[PortKey]bool, map[PortKey]bool, bool, error) { return listPorts(proc) },
		portInUse: portInUse,
		wait:      defaultWait,
		workers:   min(4, max(runtime.NumCPU(), 1)),
	}
}

func readPIDMax(proc string) int {
	b, err := os.ReadFile(filepath.Join(proc, "sys", "kernel", "pid_max")) //nolint:gosec // procfs
	if err != nil {
		return 32768
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n <= 0 || n > 1<<22 {
		return 1 << 22
	}
	return n
}

// listAllPIDs junta os processos (leitura do diretório /proc, o getdents que o ps usa) e as threads de cada um:
// kill(TID, 0) responde para thread, que não aparece no /proc de primeiro nível.
func listAllPIDs(proc string) (map[int]bool, error) {
	ents, err := os.ReadDir(proc)
	if err != nil {
		return nil, err
	}
	out := make(map[int]bool, len(ents)*2)
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		out[pid] = true
		tasks, err := os.ReadDir(filepath.Join(proc, e.Name(), "task"))
		if err != nil {
			continue
		}
		for _, t := range tasks {
			if tid, err := strconv.Atoi(t.Name()); err == nil {
				out[tid] = true
			}
		}
	}
	return out, nil
}

// pidExists pergunta ao kernel por três caminhos diferentes; um rootkit que intercepta um deles não esconde dos
// outros. EPERM também prova existência (processo de outro dono sem permissão de sinal).
func pidExists(pid int) []string {
	var checks []string
	if err := unix.Kill(pid, 0); err == nil || errors.Is(err, unix.EPERM) {
		checks = append(checks, "kill")
	}
	if _, err := unix.Getpgid(pid); err == nil || errors.Is(err, unix.EPERM) {
		checks = append(checks, "getpgid")
	}
	if _, err := unix.Getsid(pid); err == nil || errors.Is(err, unix.EPERM) {
		checks = append(checks, "getsid")
	}
	return checks
}

// listPorts lê as portas locais em /proc/net/{tcp,tcp6,udp,udp6} e no netlink (sock_diag, todas as situações).
func listPorts(proc string) (procSet, nlSet map[PortKey]bool, nlOK bool, err error) {
	procSet = map[PortKey]bool{}
	read := 0
	for _, f := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := os.ReadFile(filepath.Join(proc, "net", f)) //nolint:gosec // procfs
		if err != nil {
			continue
		}
		read++
		for _, s := range ParseNetFile(strings.TrimSuffix(f, "6"), b) {
			if _, port, err := net.SplitHostPort(s.Local); err == nil {
				if n, err := strconv.Atoi(port); err == nil && n > 0 {
					procSet[PortKey{Proto: s.Proto, Port: n}] = true
				}
			}
		}
	}
	if read == 0 {
		return nil, nil, false, errors.New("/proc/net ilegível")
	}
	nlSet = map[PortKey]bool{}
	nlOK = true
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			ports, err := diagDump(fam, proto)
			if err != nil {
				if fam == unix.AF_INET6 && errors.Is(err, unix.EAFNOSUPPORT) {
					continue
				}
				nlOK = false
				continue
			}
			name := "tcp"
			if proto == unix.IPPROTO_UDP {
				name = "udp"
			}
			for _, p := range ports {
				nlSet[PortKey{Proto: name, Port: p}] = true
			}
		}
	}
	return procSet, nlSet, nlOK, nil
}

// diagDump pede ao kernel (NETLINK_SOCK_DIAG) todos os sockets de uma família e protocolo e devolve as portas locais.
func diagDump(family, proto uint8) ([]int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_INET_DIAG)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	tv := unix.Timeval{Sec: 5}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	// nlmsghdr (16) + inet_diag_req_v2 (56): família, protocolo, extensões, preenchimento, estados e o id zerado.
	req := make([]byte, 16+56)
	binary.NativeEndian.PutUint32(req[0:], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:], unix.SOCK_DIAG_BY_FAMILY)
	binary.NativeEndian.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[8:], 1)
	req[16], req[17] = family, proto
	binary.NativeEndian.PutUint32(req[20:], 0xffffffff) // todos os estados
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var ports []int
	buf := make([]byte, 1<<16)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, err
		}
		msgs, err := parseNetlink(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			switch m.typ {
			case unix.NLMSG_DONE:
				return ports, nil
			case unix.NLMSG_ERROR:
				if len(m.data) >= 4 {
					if code := int32(binary.NativeEndian.Uint32(m.data)); code != 0 { //nolint:gosec // errno negativo do kernel
						return nil, unix.Errno(-code)
					}
				}
				return ports, nil
			case unix.SOCK_DIAG_BY_FAMILY:
				// inet_diag_msg: família, estado, timer, retrans, depois o id (porta de origem em ordem de rede).
				if len(m.data) >= 6 {
					if p := int(binary.BigEndian.Uint16(m.data[4:6])); p > 0 {
						ports = append(ports, p)
					}
				}
			}
		}
	}
	return nil, errors.New("netlink sem resposta completa")
}

type nlMsg struct {
	typ  uint16
	data []byte
}

func parseNetlink(b []byte) ([]nlMsg, error) {
	var out []nlMsg
	for len(b) >= 16 {
		l := int(binary.NativeEndian.Uint32(b[0:4]))
		if l < 16 || l > len(b) {
			return nil, fmt.Errorf("mensagem netlink com tamanho %d", l)
		}
		out = append(out, nlMsg{typ: binary.NativeEndian.Uint16(b[4:6]), data: b[16:l]})
		al := (l + 3) &^ 3
		if al > len(b) {
			break
		}
		b = b[al:]
	}
	return out, nil
}

// portInUse tenta ocupar a porta no IPv4 e no IPv6 (só IPv6) e solta na hora. No TCP usa SO_REUSEADDR: só uma
// escuta ativa recusa o bind, e um serviço que suba nesse instante com SO_REUSEADDR não é atrapalhado.
func portInUse(k PortKey) (inUse, probed bool) {
	typ := unix.SOCK_DGRAM
	if k.Proto == "tcp" {
		typ = unix.SOCK_STREAM
	}
	try := func(family int, sa unix.Sockaddr) (bool, bool) {
		fd, err := unix.Socket(family, typ|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return false, false
		}
		defer func() { _ = unix.Close(fd) }()
		if k.Proto == "tcp" {
			_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		}
		if family == unix.AF_INET6 {
			_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
		}
		err = unix.Bind(fd, sa)
		switch {
		case err == nil:
			return false, true
		case errors.Is(err, unix.EADDRINUSE):
			return true, true
		}
		return false, false // EACCES (porta privilegiada), EADDRNOTAVAIL...
	}
	in4, p4 := try(unix.AF_INET, &unix.SockaddrInet4{Port: k.Port})
	in6, p6 := try(unix.AF_INET6, &unix.SockaddrInet6{Port: k.Port})
	return in4 || in6, p4 || p6
}

// sameNetNamespace diz se a inspeção roda na rede do sistema (a mesma do PID 1); fora dela a busca por portas não
// vale.
func sameNetNamespace(proc string) bool {
	self, err1 := os.Readlink(filepath.Join(proc, "self", "ns", "net"))
	initNS, err2 := os.Readlink(filepath.Join(proc, "1", "ns", "net"))
	return err1 == nil && err2 == nil && self == initNS
}

// RunHidden faz a busca completa (processos e, na rede do sistema, portas).
func RunHidden(ctx context.Context, proc string) HiddenReport {
	started := time.Now()
	p := linuxHiddenProbes(proc)
	rep := HiddenReport{Processes: findHiddenProcesses(ctx, p)}
	if sameNetNamespace(proc) {
		rep.Ports = findHiddenPorts(ctx, p)
	} else {
		rep.Ports = HiddenPorts{Found: []HiddenPort{}, Error: "a inspeção roda em rede isolada; portas não conferidas"}
	}
	rep.Seconds = time.Since(started).Seconds()
	return rep
}
