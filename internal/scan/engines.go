package scan

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/guigallina27/vigiahost/internal/engines/clamav"
	"github.com/guigallina27/vigiahost/internal/engines/yarax"
	"github.com/guigallina27/vigiahost/internal/rules"
)

// clamdStartupWait é quanto a execução espera um clamd configurado que ainda não respondeu.
var clamdStartupWait = 3 * time.Minute

// Locais procurados para os binários dos motores, em ordem: o do pacote do produto primeiro.
var (
	yrPaths       = []string{"/usr/libexec/vigiahost/yr", "/usr/bin/yr", "/usr/local/bin/yr"}
	clamscanPaths = []string{"/usr/bin/clamscan", "/usr/local/bin/clamscan"}
)

// EngineInfo descreve o que foi encontrado no servidor; também alimenta a tela de saúde dos motores.
type EngineInfo struct {
	YR           string             `json:"yr,omitempty"`
	YRVersion    string             `json:"yr_version,omitempty"`
	RulesVersion string             `json:"rules_version,omitempty"`
	RulesFile    string             `json:"rules_file,omitempty"`
	YRError      string             `json:"yr_error,omitempty"`
	Clamd        *clamav.Config     `json:"clamd,omitempty"`
	ClamdError   string             `json:"clamd_error,omitempty"`
	Clamscan     string             `json:"clamscan,omitempty"`
	ClamVersion  clamav.VersionInfo `json:"clam_version"`
	ClamError    string             `json:"clam_error,omitempty"`
}

func firstExecutable(paths []string) string {
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// DiscoverEngines localiza e prepara os motores: compila as regras do produto em stateDir/rules e procura o
// clamd pela configuração e o clamscan. root é a raiz para a descoberta do clamd (os.DirFS("/")).
func DiscoverEngines(ctx context.Context, stateDir string, clamdCfg func() (clamav.Config, bool), extra ...yarax.Source) EngineInfo {
	var info EngineInfo
	if yr := firstExecutable(yrPaths); yr == "" {
		info.YRError = "YARA-X (yr) não encontrado"
	} else {
		info.YR = yr
		v, err := yarax.Version(ctx, yr)
		if err != nil {
			info.YRError = err.Error()
		} else {
			info.YRVersion = v
			dir := filepath.Join(stateDir, "rules")
			set, err := rules.Materialize(filepath.Join(dir, "src"), extra...)
			if err == nil {
				info.RulesVersion = set.Version
				info.RulesFile, err = rules.Compiled(ctx, yr, v, dir, set)
			}
			if err != nil {
				info.YRError = "regras: " + err.Error()
			}
		}
	}

	if cfg, ok := clamdCfg(); ok {
		c := &clamav.Client{Socket: cfg.LocalSocket}
		v, err := c.Version(ctx)
		// Logo após o boot o clamd leva até alguns minutos carregando as assinaturas antes de abrir o socket.
		for wait := time.Now().Add(clamdStartupWait); err != nil && time.Now().Before(wait) && ctx.Err() == nil; {
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
			v, err = c.Version(ctx)
		}
		if err != nil {
			info.ClamdError = "clamd em " + cfg.LocalSocket + " não respondeu: " + err.Error()
		} else {
			info.Clamd = &cfg
			info.ClamVersion = v
		}
	} else {
		info.ClamdError = "clamd não encontrado"
	}
	if cs := firstExecutable(clamscanPaths); cs != "" {
		info.Clamscan = cs
		if info.Clamd == nil {
			v, err := clamav.ClamscanVersion(ctx, cs)
			if err != nil {
				info.ClamError = err.Error()
			} else {
				info.ClamVersion = v
			}
		}
	}
	if info.ClamVersion.Database == "" {
		info.ClamVersion.Database = clamav.DatabaseVersion(os.DirFS("/"))
	}
	if info.Clamd == nil && info.Clamscan == "" {
		info.ClamError = errors.Join(errors.New(info.ClamdError), exec.ErrNotFound).Error()
	}
	return info
}

// Apply preenche a configuração da varredura com o que foi descoberto.
func (info *EngineInfo) Apply(cfg *Config) {
	if info.RulesFile != "" {
		cfg.YARA = &yarax.Scanner{Bin: info.YR, Rules: info.RulesFile, Timeout: 60}
		cfg.YARAVersion = info.YRVersion
		cfg.RulesVersion = info.RulesVersion
	}
	cfg.ClamVersion = info.ClamVersion
	if info.Clamd != nil {
		cfg.Clamd = &clamav.Client{Socket: info.Clamd.LocalSocket}
		if n := info.Clamd.Limits["MaxFileSize"]; n > 0 {
			cfg.ClamdMaxFile = n
		}
	}
	if info.Clamscan != "" {
		cfg.Clamscan = &clamav.Clamscan{Bin: info.Clamscan, MaxFileBytes: 2 << 30, MaxScanBytes: 4 << 30}
	}
}
