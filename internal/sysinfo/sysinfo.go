// Package sysinfo detecta a distribuição e as capacidades do sistema das quais o produto depende
// (systemd, cgroup v2, PSI). Lê tudo de um fs.FS para poder ser testado sem um Linux real.
package sysinfo

import (
	"bufio"
	"bytes"
	"io/fs"
	"runtime"
	"strings"
)

type Capabilities struct {
	DistroID      string   `json:"distro_id"`
	DistroVersion string   `json:"distro_version"`
	DistroName    string   `json:"distro_name"`
	DistroLike    []string `json:"distro_like,omitempty"`
	Kernel        string   `json:"kernel"`
	Arch          string   `json:"arch"`
	Systemd       bool     `json:"systemd"`
	CgroupV2      bool     `json:"cgroup_v2"`
	PSI           bool     `json:"psi"`
}

// Family agrupa distribuições pelo gerenciador de pacotes: "rhel", "debian" ou "" (desconhecida).
func (c Capabilities) Family() string {
	for _, id := range append([]string{c.DistroID}, c.DistroLike...) {
		switch id {
		case "rhel", "fedora", "centos":
			return "rhel"
		case "debian", "ubuntu":
			return "debian"
		}
	}
	return ""
}

// Detect lê as informações a partir da raiz informada (em produção, os.DirFS("/")).
func Detect(root fs.FS) Capabilities {
	c := Capabilities{Arch: runtime.GOARCH}

	osRelease, err := fs.ReadFile(root, "etc/os-release")
	if err != nil {
		osRelease, _ = fs.ReadFile(root, "usr/lib/os-release")
	}
	fields := ParseOSRelease(osRelease)
	c.DistroID = fields["ID"]
	c.DistroVersion = fields["VERSION_ID"]
	c.DistroName = fields["PRETTY_NAME"]
	if like := strings.Fields(fields["ID_LIKE"]); len(like) > 0 {
		c.DistroLike = like
	}

	if kernel, err := fs.ReadFile(root, "proc/sys/kernel/osrelease"); err == nil {
		c.Kernel = strings.TrimSpace(string(kernel))
	}
	// Mesmo critério do sd_booted(): o diretório só existe quando o systemd é o init em execução.
	c.Systemd = isDir(root, "run/systemd/system")
	c.CgroupV2 = exists(root, "sys/fs/cgroup/cgroup.controllers")
	c.PSI = exists(root, "proc/pressure/cpu")
	return c
}

// ParseOSRelease interpreta o formato de os-release(5): CHAVE=valor, com aspas simples ou duplas opcionais.
func ParseOSRelease(data []byte) map[string]string {
	out := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		out[key] = unquote(value)
	}
	return out
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
		if strings.ContainsRune(v, '\\') {
			var b strings.Builder
			escaped := false
			for _, r := range v {
				if !escaped && r == '\\' {
					escaped = true
					continue
				}
				escaped = false
				b.WriteRune(r)
			}
			v = b.String()
		}
	}
	return v
}

func exists(root fs.FS, name string) bool {
	_, err := fs.Stat(root, name)
	return err == nil
}

func isDir(root fs.FS, name string) bool {
	info, err := fs.Stat(root, name)
	return err == nil && info.IsDir()
}
