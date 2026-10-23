package lmd

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

// As fixtures em testdata foram capturadas no laboratório (LMD 2.0.1, assinaturas 2026052490478) com os arquivos
// entregues como /proc/131/fd/10..14: EICAR (SHA-256), EICAR em ZIP (HEX), PHP ofuscado inerte do corpus (HEX),
// um texto limpo e o marcador do VigiaHost (que o LMD não conhece).
const fixtureScanID = "261022-2001.201"

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func wantFixtureHits(t *testing.T, rep Report) {
	t.Helper()
	want := []Hit{
		{Signature: "{SHA256}test.test.eicar.29805", Type: "SHA256", File: "/proc/131/fd/10",
			Hash: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"},
		{Signature: "{HEX}test.test.eicar", Type: "HEX", File: "/proc/131/fd/11", Hash: "692e3d3d05c8c669ea915e7a8ed4f23f"},
		{Signature: "{HEX}php.inject.generic.564", Type: "HEX", File: "/proc/131/fd/12", Hash: "4ad3b466a91f33c89ce903406a288a07"},
	}
	if len(rep.Hits) != len(want) {
		t.Fatalf("detecções = %+v", rep.Hits)
	}
	for i, h := range want {
		if rep.Hits[i] != h {
			t.Errorf("detecção %d = %+v, esperado %+v", i, rep.Hits[i], h)
		}
	}
	if rep.ScanID != fixtureScanID || rep.Version != "2.0.1" || rep.SigVersion != "2026052490478" || rep.HashType != "sha256" {
		t.Errorf("cabeçalho = %+v", rep)
	}
	if rep.TotalFiles != 5 || rep.TotalHits != 3 || rep.TotalQuarantined != 0 || rep.QuarantineOn {
		t.Errorf("totais = %+v", rep)
	}
}

func TestParseJSONReportFixture(t *testing.T) {
	rep, err := ParseJSONReport(readFixture(t, "report-2.0.1.json"), fixtureScanID)
	if err != nil {
		t.Fatal(err)
	}
	wantFixtureHits(t, rep)
}

func TestParseJSONReportRejects(t *testing.T) {
	data := readFixture(t, "report-2.0.1.json")
	if _, err := ParseJSONReport(data, "261022-2001.999"); err == nil {
		t.Error("sessão ausente no relatório aceita")
	}
	v2 := strings.Replace(string(data), `"schema_version": "1.2"`, `"schema_version": "2.0"`, 1)
	if _, err := ParseJSONReport([]byte(v2), fixtureScanID); err == nil {
		t.Error("esquema 2.x aceito")
	}
	if _, err := ParseJSONReport([]byte("maldet: erro\n"), fixtureScanID); err == nil {
		t.Error("texto aceito como JSON")
	}
	quar := strings.Replace(string(data), `"total_quarantined": 0`, `"total_quarantined": 1`, 1)
	rep, err := ParseJSONReport([]byte(quar), fixtureScanID)
	if err != nil || rep.TotalQuarantined != 1 {
		t.Errorf("quarentena informada pelo LMD não chegou ao chamador: %+v %v", rep, err)
	}
}

func TestParseSessionTSVFixture(t *testing.T) {
	rep, err := ParseSessionTSV(readFixture(t, "session-2.0.1.tsv"), fixtureScanID)
	if err != nil {
		t.Fatal(err)
	}
	// O TSV não traz o estado da quarentena: o campo de destino "-" significa "não movido".
	wantFixtureHits(t, rep)
}

func TestParseSessionTSVRejects(t *testing.T) {
	data := readFixture(t, "session-2.0.1.tsv")
	if _, err := ParseSessionTSV(data, "261022-2001.999"); err == nil {
		t.Error("sessão de outro identificador aceita")
	}
	body := data[strings.IndexByte(string(data), '\n')+1:]
	if _, err := ParseSessionTSV(body, fixtureScanID); err == nil {
		t.Error("sessão sem cabeçalho aceita")
	}
	moved := strings.Replace(string(data), "\t/proc/131/fd/10\t-\t", "\t/proc/131/fd/10\t/usr/local/maldetect/quarantine/x\t", 1)
	rep, err := ParseSessionTSV([]byte(moved), fixtureScanID)
	if err != nil || rep.TotalQuarantined != 1 || !rep.Hits[0].Quarantined {
		t.Errorf("arquivo movido para a quarentena não foi percebido: %+v %v", rep, err)
	}
}

func TestScanIDFromOutput(t *testing.T) {
	if got := ScanIDFromOutput(readFixture(t, "stdout-2.0.1.txt")); got != fixtureScanID {
		t.Errorf("sessão = %q", got)
	}
	if got := ScanIDFromOutput([]byte("maldet --report $(id)\n")); got != "" {
		t.Errorf("sessão inválida aceita: %q", got)
	}
	for _, bad := range []string{"", "261022-2001", "../../etc", "261022-2001.201;rm", "261022-2001.201\n"} {
		if ScanIDPattern.MatchString(bad) {
			t.Errorf("identificador %q aceito", bad)
		}
	}
}

func TestFDIndex(t *testing.T) {
	fds := map[int]int{10: 0, 11: 1}
	cases := []struct {
		path string
		idx  int
		ok   bool
	}{
		{"/proc/131/fd/10", 0, true},
		{"/proc/131/fd/11", 1, true},
		{"/proc/131/fd/12", 0, false},     // fora do lote
		{"/proc/132/fd/10", 0, false},     // outro processo
		{"/proc/131/fd/010", 0, false},    // forma não canônica
		{"/proc/131/fd/10/x", 0, false},   // caminho dentro do descritor
		{"/var/www/a.php", 0, false},      // nome de arquivo nunca vale
		{"/proc/131/fd/10\n/x", 0, false}, // quebra de linha
	}
	for _, c := range cases {
		i, ok := FDIndex(c.path, 131, fds)
		if ok != c.ok || (ok && i != c.idx) {
			t.Errorf("FDIndex(%q) = %d, %v", c.path, i, ok)
		}
	}
}

func TestCoOptions(t *testing.T) {
	for _, yara := range []bool{true, false} {
		opts := coOptions(yara, 4)
		for _, must := range []string{"quarantine_hits=0", "quarantine_clean=0", "quarantine_suspend_user=0",
			"quarantine_on_error=0", "scan_clamscan=0", "email_alert=0", "post_scan_hook_on=digest", "scan_workers=4"} {
			if !strings.Contains(opts, must) {
				t.Errorf("opções sem %s: %s", must, opts)
			}
		}
		if strings.ContainsAny(opts, "$`|&() \n") {
			t.Errorf("opções com caractere que o LMD recusa: %s", opts)
		}
		if yara != strings.Contains(opts, "scan_yara=1") {
			t.Errorf("estágio YARA = %v, opções %s", yara, opts)
		}
	}
}

func fakeInstall(version string) fstest.MapFS {
	return fstest.MapFS{
		Dir + "/maldet":                     {Data: []byte("#!/usr/bin/env bash\nlmd_version=\"" + version + "\"\n"), Mode: 0o755},
		Dir + "/internals/internals.conf":   {Data: []byte("inspath=x\n")},
		Dir + "/internals/lmd.lib.sh":       {Data: []byte("#\n")},
		Dir + "/sigs/maldet.sigs.ver":       {Data: []byte("2026052490478\n")},
		Dir + "/sigs/md5v2.dat":             {Data: []byte("a:1:{MD5}x.1\nb:2:{MD5}x.2\n\n")},
		Dir + "/sigs/sha256v2.dat":          {Data: []byte("c:3:{SHA256}x.3\n")},
		Dir + "/sigs/hex.dat":               {Data: []byte("41:{HEX}x.4\n42:{HEX}x.5\n43:{HEX}x.6\n")},
		Dir + "/sigs/csig.dat":              {Data: []byte("# comentário\nx\n")},
		Dir + "/sigs/rfxn.yara":             {Data: []byte("rule a { condition: true }\nprivate rule b { condition: true }\n// rule c\n")},
		Dir + "/sigs/custom.hex.dat":        {Data: []byte("44:{HEX}meu.1\n")},
		Dir + "/sigs/custom.yara.d/x.yar":   {Data: []byte("rule d { condition: false }\n")},
		"var/lib/clamav/rfxn.hdb":           {Data: []byte("x")},
		"var/lib/clamav/main.cvd":           {Data: []byte("x")},
		"usr/local/share/clamav/rfxn.yara":  {Data: []byte("x")},
		"usr/local/share/clamav/daily.cld":  {Data: []byte("x")},
		"usr/local/share/clamav/other.ndb":  {Data: []byte("x")},
		"usr/local/share/clamav/rfxn.ndb.x": {Data: []byte("x")},
	}
}

func TestDiscover(t *testing.T) {
	old := trusted
	trusted = func(fs.FileInfo) bool { return true }
	defer func() { trusted = old }()

	in, err := Discover(fakeInstall("2.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if in.Version != "2.0.1" || in.SigVersion != "2026052490478" || in.SigDate != "2026-05-24" {
		t.Errorf("instalação = %+v", in)
	}
	want := Counts{MD5: 2, SHA256: 1, HEX: 3, CSIG: 1, YARA: 2, User: 2}
	if in.Signatures != want {
		t.Errorf("assinaturas = %+v, esperado %+v", in.Signatures, want)
	}
	if strings.Join(in.ClamAVLinked, " ") != "/var/lib/clamav/rfxn.hdb /usr/local/share/clamav/rfxn.yara" {
		t.Errorf("assinaturas do LMD no ClamAV = %v", in.ClamAVLinked)
	}

	if _, err := Discover(fakeInstall("1.6.6")); !errors.Is(err, ErrUnsupported) {
		t.Errorf("1.6.6 deveria ser recusada: %v", err)
	}
	if _, err := Discover(fstest.MapFS{}); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("sem instalação: %v", err)
	}
	trusted = func(i fs.FileInfo) bool { return i.Name() != "internals" }
	if _, err := Discover(fakeInstall("2.0.1")); err == nil || !strings.Contains(err.Error(), "insegura") {
		t.Errorf("internals gravável por outros deveria ser recusado: %v", err)
	}
}

func TestCleanStderr(t *testing.T) {
	in := "x/elog_lib.sh: line 424: /var/log/maldet/event_log: Read-only file system\n" +
		"chmod: changing permissions of '/var/log/maldet': Read-only file system\n" +
		"maldet(1): {scan} erro real\n"
	if got := cleanStderr([]byte(in)); got != "maldet(1): {scan} erro real" {
		t.Errorf("stderr = %q", got)
	}
}

func FuzzParseSessionTSV(f *testing.F) {
	data, err := os.ReadFile("testdata/session-2.0.1.tsv")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte("#LMD:v1\tscan\t" + fixtureScanID + "\n\t\t\t\t\t\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		rep, err := ParseSessionTSV(b, fixtureScanID)
		if err == nil {
			for _, h := range rep.Hits {
				if len(h.File) > 4096 || len(h.Signature) > 256 {
					t.Fatalf("campo sem limite: %+v", h)
				}
			}
		}
	})
}

func FuzzParseJSONReport(f *testing.F) {
	data, err := os.ReadFile("testdata/report-2.0.1.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(`{"schema_version":"1.0","reports":[{"scan_id":"` + fixtureScanID + `","hits":[{}]}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		rep, err := ParseJSONReport(b, fixtureScanID)
		if err == nil && rep.ScanID != fixtureScanID {
			t.Fatalf("sessão trocada: %q", rep.ScanID)
		}
	})
}
