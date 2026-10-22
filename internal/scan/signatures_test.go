package scan

import (
	"testing"

	"github.com/guigallina27/vigiahost/internal/report"
)

func TestClamSource(t *testing.T) {
	cases := map[string]string{
		"Eicar-Test-Signature":                   "clamav",
		"Php.Webshell.Generic-1":                 "clamav",
		"YARA.minha_regra.UNOFFICIAL":            "clamav-unofficial",
		"{HEX}php.inject.generic.564.UNOFFICIAL": SourceRFXN,
		"{MD5}test.test.eicar.32555.UNOFFICIAL":  SourceRFXN,
		"{SHA256}x.1.UNOFFICIAL":                 SourceRFXN,
	}
	for sig, want := range cases {
		if got := ClamSource(sig); got != want {
			t.Errorf("ClamSource(%q) = %q, esperado %q", sig, got, want)
		}
	}
}

func TestClassifyLMDSignature(t *testing.T) {
	cases := []struct {
		sig string
		cat report.Category
		sev report.Severity
	}{
		{"{SHA256}test.test.eicar.29805", report.CategoryTest, report.SeverityInfo},
		{"{HEX}test.test.eicar", report.CategoryTest, report.SeverityInfo},
		{"{HEX}php.cmdshell.r57.322", report.CategoryWebshell, report.SeverityCritical},
		{"{YARA}php.backdoor.x", report.CategoryWebshell, report.SeverityCritical},
		{"{HEX}php.inject.generic.564", report.CategorySuspicious, report.SeverityHigh},
		{"{HEX}base64.inject.unclassed.1", report.CategorySuspicious, report.SeverityHigh},
		{"{MD5}linux.miner.xmrig.1", report.CategoryMiner, report.SeverityHigh},
		{"{HEX}perl.ircbot.pscan.1", report.CategoryMalware, report.SeverityHigh},
	}
	for _, c := range cases {
		cat, sev := ClassifyLMDSignature(c.sig)
		if cat != c.cat || sev != c.sev {
			t.Errorf("%s = %s/%s, esperado %s/%s", c.sig, cat, sev, c.cat, c.sev)
		}
	}
	// No clamd, as assinaturas do LMD chegam com o sufixo .UNOFFICIAL e seguem a mesma classificação.
	if cat, _ := ClassifyClamSignature("{HEX}php.cmdshell.r57.322.UNOFFICIAL"); cat != report.CategoryWebshell {
		t.Errorf("assinatura do LMD no clamd classificada como %s", cat)
	}
}
