package clamav

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
)

func TestParseReply(t *testing.T) {
	cases := map[string]Verdict{
		"fd[10]: OK":                                          {},
		"stream: Eicar-Test-Signature FOUND":                  {Found: true, Signature: "Eicar-Test-Signature"},
		"fd[3]: Win.Test.EICAR_HDB-1 FOUND":                   {Found: true, Signature: "Win.Test.EICAR_HDB-1"},
		"fd[3]: Heuristics.Limits.Exceeded.MaxFileSize FOUND": {Found: true, Signature: "Heuristics.Limits.Exceeded.MaxFileSize"},
	}
	for in, want := range cases {
		got := ParseReply(in)
		if got.Found != want.Found || got.Signature != want.Signature || got.Err != nil {
			t.Errorf("ParseReply(%q) = %+v", in, got)
		}
	}
	for _, bad := range []string{"fd[3]: Can't open file ERROR", "lixo", "fd[3]: talvez"} {
		if ParseReply(bad).Err == nil {
			t.Errorf("ParseReply(%q) deveria falhar", bad)
		}
	}
}

func TestParseVersion(t *testing.T) {
	v := ParseVersion("ClamAV 1.4.6/27800/Wed Oct 22 08:00:00 2026\n")
	if v.Engine != "1.4.6" || v.Database != "27800" || v.BuiltAt != "Wed Oct 22 08:00:00 2026" {
		t.Fatalf("%+v", v)
	}
}

func TestParseConfigEDiscover(t *testing.T) {
	conf := "# exemplo\nLocalSocket /run/clamd.scan/clamd.sock\nMaxFileSize 25M\nMaxScanSize 100M\nMaxRecursion 16\nMaxThreads 10\n"
	cfg := ParseConfig([]byte(conf))
	if cfg.LocalSocket != "/run/clamd.scan/clamd.sock" || cfg.Limits["MaxFileSize"] != 25<<20 || cfg.Limits["MaxRecursion"] != 16 {
		t.Fatalf("%+v", cfg)
	}
	if ParseConfig([]byte("Example\nLocalSocket /x\n")).LocalSocket != "" {
		t.Fatal("arquivo de exemplo não deveria valer")
	}
	root := fstest.MapFS{
		"etc/clamd.d/scan.conf": {Data: []byte("Example\n")},
		"etc/clamav/clamd.conf": {Data: []byte(conf)},
	}
	got, ok := Discover(root)
	if !ok || got.File != "/etc/clamav/clamd.conf" {
		t.Fatalf("Discover: %+v %v", got, ok)
	}
	if _, ok := Discover(fstest.MapFS{}); ok {
		t.Fatal("sem clamd não deveria achar nada")
	}
}

// fakeClamd responde INSTREAM conferindo o conteúdo recebido.
func fakeClamd(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("socket Unix")
	}
	sock := filepath.Join(t.TempDir(), "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				cmd := make([]byte, 0, 16)
				b := make([]byte, 1)
				for {
					if _, err := conn.Read(b); err != nil {
						return
					}
					if b[0] == 0 {
						break
					}
					cmd = append(cmd, b[0])
				}
				switch string(cmd) {
				case "zPING":
					_, _ = conn.Write([]byte("PONG\x00"))
				case "zVERSION":
					_, _ = conn.Write([]byte("ClamAV 1.4.6/27800/Wed Oct 22 08:00:00 2026\x00"))
				case "zINSTREAM":
					var data bytes.Buffer
					var size [4]byte
					for {
						if _, err := io.ReadFull(conn, size[:]); err != nil {
							return
						}
						n := binary.BigEndian.Uint32(size[:])
						if n == 0 {
							break
						}
						if _, err := io.CopyN(&data, conn, int64(n)); err != nil {
							return
						}
					}
					if strings.Contains(data.String(), "MALWARE") {
						_, _ = conn.Write([]byte("stream: Teste.Falso FOUND\x00"))
					} else {
						_, _ = conn.Write([]byte("stream: OK\x00"))
					}
				}
			}()
		}
	}()
	return sock
}

func TestClientInstream(t *testing.T) {
	sock := fakeClamd(t)
	c := &Client{Socket: sock}
	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	v, err := c.Version(ctx)
	if err != nil || v.Engine != "1.4.6" {
		t.Fatalf("%+v %v", v, err)
	}
	big := strings.Repeat("a", 200<<10) + "MALWARE"
	if got := c.ScanStream(ctx, strings.NewReader(big)); !got.Found || got.Signature != "Teste.Falso" {
		t.Fatalf("%+v", got)
	}
	if got := c.ScanStream(ctx, strings.NewReader("limpo")); got.Found || got.Err != nil {
		t.Fatalf("%+v", got)
	}
}

func TestDatabaseVersion(t *testing.T) {
	head := "ClamAV-VDB:22 Oct 2026 08-00 +0000:27800:2071234:90:md5:sig:builder:1761120000"
	root := fstest.MapFS{"var/lib/clamav/daily.cld": {Data: []byte(head + strings.Repeat(" ", 512-len(head)))}}
	if v := DatabaseVersion(root); v != "27800" {
		t.Fatalf("versão: %q", v)
	}
	if v := DatabaseVersion(fstest.MapFS{}); v != "" {
		t.Fatalf("sem banco: %q", v)
	}
}
