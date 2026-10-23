package scan

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/guigallina27/vigiahost/internal/engines/clamav"
	"github.com/guigallina27/vigiahost/internal/engines/lmd"
	"github.com/guigallina27/vigiahost/internal/engines/yarax"
	"github.com/guigallina27/vigiahost/internal/rules"
)

// DiscoverOptions controla o custo da descoberta: a execução compila as regras e espera o clamd subir; a tela de
// saúde só consulta versões.
type DiscoverOptions struct {
	Compile   bool
	ClamdWait time.Duration // quanto esperar um clamd configurado que ainda não respondeu (carregando assinaturas)
	// UserRules é o diretório das fontes locais de regras (rules.UserDir); vazio compila só as embarcadas.
	UserRules string
	// DisabledRules são as fontes desativadas pelo administrador; Trigger vai para o status da compilação.
	DisabledRules []string
	Trigger       string
}

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
	// RulesWarnings cita fontes de regras que ficaram fora do conjunto compilado (erro ou recusa).
	RulesWarnings []string `json:"rules_warnings,omitempty"`
	// LMD é a instalação do Linux Malware Detect encontrada (também quando não pode ser usada: versão antiga,
	// permissões); LMDError explica por que não pode.
	LMD      *lmd.Install `json:"lmd,omitempty"`
	LMDError string       `json:"lmd_error,omitempty"`
}

// YRBinary devolve o yr encontrado (o do pacote do produto primeiro) ou vazio.
func YRBinary() string { return firstExecutable(yrPaths) }

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
func DiscoverEngines(ctx context.Context, stateDir string, opts DiscoverOptions, clamdCfg func() (clamav.Config, bool)) EngineInfo {
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
		}
		if err == nil && opts.Compile {
			dir := filepath.Join(stateDir, "rules")
			set, compiled, st, err := rules.Prepare(ctx, yr, v, dir, rules.PrepareOptions{UserDir: opts.UserRules,
				Disabled: opts.DisabledRules, Trigger: opts.Trigger})
			if err == nil {
				info.RulesVersion, info.RulesFile = set.Version, compiled
			} else {
				info.YRError = "regras: " + err.Error()
			}
			for _, src := range st.Sources {
				if src.State == rules.StateError || src.State == rules.StateRefused {
					info.RulesWarnings = append(info.RulesWarnings, "fonte de regras "+src.Name+" fora do conjunto: "+src.Error)
				}
			}
		}
	}

	if cfg, ok := clamdCfg(); ok {
		c := &clamav.Client{Socket: cfg.LocalSocket}
		v, err := c.Version(ctx)
		// Logo após o boot o clamd leva até alguns minutos carregando as assinaturas antes de abrir o socket.
		for wait := time.Now().Add(opts.ClamdWait); err != nil && time.Now().Before(wait) && ctx.Err() == nil; {
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
	if in, err := lmd.Discover(os.DirFS("/")); err != nil {
		info.LMDError = err.Error()
		if in.Version != "" {
			info.LMD = &in
		}
	} else {
		info.LMD = &in
	}
	return info
}

// LMDVersion identifica motor, assinaturas e estágios do LMD para o cache e a cobertura.
func LMDVersion(s *lmd.Scanner) string {
	if s == nil {
		return ""
	}
	v := s.Install.Version + "/" + s.Install.SigVersion
	if s.YRDir != "" {
		v += "/yara"
	}
	return v
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
	// LMD só quando o pedido liga (desligado por padrão) e a instalação pode ser usada.
	if cfg.Request.LMD {
		switch {
		case info.LMD != nil && info.LMDError == "":
			sc := &lmd.Scanner{Install: *info.LMD, Work: filepath.Join(cfg.OutDir, "lmd"), Workers: cfg.Request.Profile.Workers}
			if info.YR != "" && info.YRVersion != "" {
				sc.YRDir = filepath.Dir(info.YR)
			}
			cfg.LMD = sc
		case info.LMDError != "":
			cfg.LMDError = info.LMDError
		default:
			cfg.LMDError = lmd.ErrNotInstalled.Error()
		}
	}
}
