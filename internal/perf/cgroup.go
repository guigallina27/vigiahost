package perf

import (
	"bufio"
	"bytes"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"sync"
)

// Usage é o consumo de uma execução.
type Usage struct {
	CPUSeconds      float64
	MemoryPeakBytes int64
	// Source é "cgroup" (unidade inteira, com os processos filhos dos motores) ou "rusage" (só este processo e os
	// filhos que ele esperou, sem o cache de páginas).
	Source string
}

// Cgroup lê CPU e memória do cgroup v2 da unidade transitória da execução.
type Cgroup struct {
	root fs.FS
	dir  string // relativo à raiz: sys/fs/cgroup/vigiahost.slice/vigiahost-run-<id>.service

	mu   sync.Mutex
	peak int64
}

// OwnCgroup encontra o cgroup do processo a partir de /proc/self/cgroup. Só vale dentro de uma unidade de execução
// do VigiaHost (vigiahost-run-*.service): fora dela o cgroup é de outra coisa (sessão, serviço) e os números não
// seriam da execução. Devolve nil quando não há cgroup v2 ou a unidade não é de execução.
func OwnCgroup(root fs.FS, procSelfCgroup []byte) *Cgroup {
	sc := bufio.NewScanner(bytes.NewReader(procSelfCgroup))
	for sc.Scan() {
		rel, ok := strings.CutPrefix(sc.Text(), "0::/")
		if !ok {
			continue
		}
		if strings.Contains(rel, "..") {
			return nil
		}
		rel = path.Clean(rel)
		base := path.Base(rel)
		if !strings.HasPrefix(base, "vigiahost-run-") || !strings.HasSuffix(base, ".service") {
			return nil
		}
		dir := path.Join("sys/fs/cgroup", rel)
		if _, err := fs.Stat(root, path.Join(dir, "cpu.stat")); err != nil {
			return nil
		}
		return &Cgroup{root: root, dir: dir}
	}
	return nil
}

// Sample lê a memória atual e guarda o maior valor visto (para kernels sem memory.peak, anteriores ao 5.19).
func (c *Cgroup) Sample() {
	if c == nil {
		return
	}
	if v, ok := c.readInt("memory.current"); ok {
		c.mu.Lock()
		c.peak = max(c.peak, v)
		c.mu.Unlock()
	}
}

// Usage devolve a CPU consumida desde o início da unidade e o pico de memória.
func (c *Cgroup) Usage() (Usage, bool) {
	if c == nil {
		return Usage{}, false
	}
	data, err := fs.ReadFile(c.root, path.Join(c.dir, "cpu.stat"))
	if err != nil {
		return Usage{}, false
	}
	var usec int64
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "usage_usec "); ok {
			usec, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		}
	}
	c.Sample()
	c.mu.Lock()
	peak := c.peak
	c.mu.Unlock()
	if v, ok := c.readInt("memory.peak"); ok {
		peak = max(peak, v)
	}
	return Usage{CPUSeconds: float64(usec) / 1e6, MemoryPeakBytes: peak, Source: "cgroup"}, true
}

func (c *Cgroup) readInt(name string) (int64, bool) {
	data, err := fs.ReadFile(c.root, path.Join(c.dir, name))
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	return v, err == nil
}
