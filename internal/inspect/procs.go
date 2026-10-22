package inspect

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"net"
	"strconv"
	"strings"
)

// Process é o instantâneo de um processo gravado em processes.json (segredos mascarados).
type Process struct {
	PID        int      `json:"pid"`
	PPID       int      `json:"ppid"`
	UID        uint32   `json:"uid"`
	User       string   `json:"user,omitempty"`
	Comm       string   `json:"comm"`
	Cmdline    []string `json:"cmdline,omitempty"`
	Exe        string   `json:"exe"`
	ExeDeleted bool     `json:"exe_deleted,omitempty"`
	ExeMemfd   bool     `json:"exe_memfd,omitempty"`
	ExeSHA256  string   `json:"exe_sha256,omitempty"`
	Package    string   `json:"package,omitempty"`
	Unit       string   `json:"unit,omitempty"`
	Cgroup     string   `json:"cgroup,omitempty"`
	StartTime  uint64   `json:"start_ticks,omitempty"`
	CPUPercent float64  `json:"cpu_percent"`
	RSSBytes   int64    `json:"rss_bytes"`
	Threads    int      `json:"threads"`
	Listening  []string `json:"listening,omitempty"`
	Connected  []string `json:"connected,omitempty"`
	Flags      []string `json:"flags,omitempty"`
	// Campos internos (não gravados).
	cpuTicks   uint64
	sockets    []uint64
	netns      string
	ldPreload  string
	kthreadArg bool
}

// parseStat lê PPID, tiques de CPU (utime+stime), início e threads de /proc/PID/stat. O nome do processo fica entre
// parênteses e pode conter espaços e parênteses: o resto começa depois do último ")".
func parseStat(b []byte) (ppid int, ticks, start uint64, threads int, ok bool) {
	i := bytes.LastIndexByte(b, ')')
	if i < 0 || i+2 >= len(b) {
		return 0, 0, 0, 0, false
	}
	f := strings.Fields(string(b[i+2:]))
	// Depois do nome: estado(0) ppid(1) ... utime(11) stime(12) ... num_threads(17) ... starttime(19).
	if len(f) < 20 {
		return 0, 0, 0, 0, false
	}
	ppid, _ = strconv.Atoi(f[1])
	ut, _ := strconv.ParseUint(f[11], 10, 64)
	st, _ := strconv.ParseUint(f[12], 10, 64)
	threads, _ = strconv.Atoi(f[17])
	start, _ = strconv.ParseUint(f[19], 10, 64)
	return ppid, ut + st, start, threads, true
}

// parseStatus devolve UID real e RSS de /proc/PID/status.
func parseStatus(b []byte) (uid uint32, rss int64) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		l := sc.Text()
		if v, ok := strings.CutPrefix(l, "Uid:"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				u, _ := strconv.ParseUint(f[0], 10, 32)
				uid = uint32(u)
			}
		} else if v, ok := strings.CutPrefix(l, "VmRSS:"); ok {
			f := strings.Fields(v)
			if len(f) > 0 {
				kb, _ := strconv.ParseInt(f[0], 10, 64)
				rss = kb << 10
			}
		}
	}
	return uid, rss
}

// unitFromCgroup extrai a unidade systemd do caminho do cgroup v2 ("0::/system.slice/nginx.service").
func unitFromCgroup(b []byte) (cgroup, unit string) {
	for _, l := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(l, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" || cgroup == "" {
			cgroup = parts[2]
		}
	}
	segs := strings.Split(cgroup, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		s := segs[i]
		if strings.HasSuffix(s, ".service") || strings.HasSuffix(s, ".scope") {
			return cgroup, s
		}
	}
	return cgroup, ""
}

// splitCmdline separa /proc/PID/cmdline (argumentos terminados em NUL).
func splitCmdline(b []byte) []string {
	b = bytes.TrimRight(b, "\x00")
	if len(b) == 0 {
		return nil
	}
	parts := bytes.Split(b, []byte{0})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, string(p))
		if len(out) >= 256 {
			break
		}
	}
	return out
}

// envValue procura uma variável em /proc/PID/environ.
func envValue(b []byte, name string) string {
	prefix := []byte(name + "=")
	for _, kv := range bytes.Split(b, []byte{0}) {
		if bytes.HasPrefix(kv, prefix) {
			return string(kv[len(prefix):])
		}
	}
	return ""
}

// Socket é uma linha de /proc/net/{tcp,tcp6,udp,udp6}.
type Socket struct {
	Proto  string
	Local  string
	Remote string
	RPort  int
	State  int
	Inode  uint64
}

const (
	tcpEstablished = 1
	tcpListen      = 10
)

func parseHexAddr(s string) (string, int, bool) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return "", 0, false
	}
	raw := make([]byte, len(host)/2)
	for i := range raw {
		v, err := strconv.ParseUint(host[2*i:2*i+2], 16, 8)
		if err != nil {
			return "", 0, false
		}
		raw[i] = byte(v)
	}
	// O kernel grava cada palavra de 32 bits na ordem do host (little-endian nas arquiteturas suportadas).
	for i := 0; i+4 <= len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	ip := net.IP(raw)
	if len(raw) != 4 && len(raw) != 16 {
		return "", 0, false
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(p))), int(p), true
}

// ParseNetFile lê uma tabela de sockets do /proc.
func ParseNetFile(proto string, b []byte) []Socket {
	var out []Socket
	for i, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 10 {
			continue
		}
		local, _, ok1 := parseHexAddr(f[1])
		remote, rport, ok2 := parseHexAddr(f[2])
		st, err := strconv.ParseUint(f[3], 16, 8)
		ino, err2 := strconv.ParseUint(f[9], 10, 64)
		if !ok1 || !ok2 || err != nil || err2 != nil {
			continue
		}
		out = append(out, Socket{Proto: proto, Local: local, Remote: remote, RPort: rport, State: int(st), Inode: ino})
	}
	return out
}

// Portas típicas de pools de mineração (stratum).
var minerPorts = map[int]bool{3333: true, 4444: true, 5555: true, 6666: true, 7777: true, 9999: true,
	14433: true, 14444: true, 45560: true, 45700: true, 10128: true, 20128: true}

// usernames lê /etc/passwd (UID → nome) para a tela de processos.
func usernames(root fs.FS) map[uint32]string {
	m := map[uint32]string{}
	b, err := fs.ReadFile(root, "etc/passwd")
	if err != nil {
		return m
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 3 {
			continue
		}
		var uid uint32
		if _, err := fmt.Sscanf(f[2], "%d", &uid); err == nil {
			m[uid] = f[0]
		}
	}
	return m
}
