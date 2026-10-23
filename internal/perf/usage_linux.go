package perf

import "syscall"

// ProcessUsage é a alternativa sem cgroup v2: CPU deste processo e dos filhos já esperados, e o maior RSS entre eles.
func ProcessUsage() Usage {
	var self, children syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &self) != nil {
		return Usage{}
	}
	_ = syscall.Getrusage(syscall.RUSAGE_CHILDREN, &children)
	cpu := tv(self.Utime) + tv(self.Stime) + tv(children.Utime) + tv(children.Stime)
	return Usage{CPUSeconds: cpu, MemoryPeakBytes: max(self.Maxrss, children.Maxrss) << 10, Source: "rusage"}
}

func tv(t syscall.Timeval) float64 { return float64(t.Sec) + float64(t.Usec)/1e6 }
