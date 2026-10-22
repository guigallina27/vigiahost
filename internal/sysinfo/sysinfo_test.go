package sysinfo

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestDetectAlmaLinux(t *testing.T) {
	root := fstest.MapFS{
		"etc/os-release": {Data: []byte(`NAME="AlmaLinux"
VERSION_ID="9.8"
ID="almalinux"
ID_LIKE="rhel centos fedora"
PRETTY_NAME="AlmaLinux 9.8 (Olive Jaguar)"
`)},
		"proc/sys/kernel/osrelease":        {Data: []byte("5.14.0-611.el9.x86_64\n")},
		"run/systemd/system":               {Mode: fs.ModeDir | 0o755},
		"sys/fs/cgroup/cgroup.controllers": {Data: []byte("cpu io memory pids\n")},
		"proc/pressure/cpu":                {Data: []byte("some avg10=0.00\n")},
	}
	c := Detect(root)
	if c.DistroID != "almalinux" || c.DistroVersion != "9.8" {
		t.Fatalf("distribuição incorreta: %+v", c)
	}
	if c.Family() != "rhel" {
		t.Errorf("família = %q, esperado rhel", c.Family())
	}
	if !c.Systemd || !c.CgroupV2 || !c.PSI {
		t.Errorf("capacidades não detectadas: %+v", c)
	}
	if c.Kernel != "5.14.0-611.el9.x86_64" {
		t.Errorf("kernel = %q", c.Kernel)
	}
}

func TestDetectContainerSemSystemd(t *testing.T) {
	root := fstest.MapFS{
		"usr/lib/os-release": {Data: []byte("ID=debian\nVERSION_ID=\"13\"\nPRETTY_NAME='Debian GNU/Linux 13 (trixie)'\n")},
		// Arquivo comum no lugar do diretório não conta como systemd em execução.
		"run/systemd/system": {Data: []byte("x")},
	}
	c := Detect(root)
	if c.DistroID != "debian" || c.DistroName != "Debian GNU/Linux 13 (trixie)" {
		t.Fatalf("os-release alternativo não lido: %+v", c)
	}
	if c.Family() != "debian" {
		t.Errorf("família = %q, esperado debian", c.Family())
	}
	if c.Systemd || c.CgroupV2 || c.PSI {
		t.Errorf("capacidades indevidas: %+v", c)
	}
}

func TestParseOSReleaseEscapesEComentarios(t *testing.T) {
	got := ParseOSRelease([]byte("# comentário\nNAME=\"Nome \\\"com\\\" aspas\"\nINVALIDA\n=sem-chave\nID=ubuntu\n"))
	if got["NAME"] != `Nome "com" aspas` {
		t.Errorf("NAME = %q", got["NAME"])
	}
	if got["ID"] != "ubuntu" || len(got) != 2 {
		t.Errorf("resultado inesperado: %v", got)
	}
}
