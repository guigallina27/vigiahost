package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/guigallina27/vigiahost/internal/version"
)

// Change é uma alteração feita no sistema, com o necessário para desfazê-la.
type Change struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"` // file, service
	Path    string    `json:"path,omitempty"`
	Unit    string    `json:"unit,omitempty"`
	Created bool      `json:"created,omitempty"` // o arquivo não existia antes
	Backup  string    `json:"backup,omitempty"`  // cópia do arquivo anterior
	Prior   *Prior    `json:"prior,omitempty"`   // estado da unidade antes do primeiro apply
	At      time.Time `json:"at"`
}

// Prior é o estado de uma unidade antes de o setup mexer nela.
type Prior struct {
	Enabled bool `json:"enabled"`
	Active  bool `json:"active"`
}

// Manifest registra tudo que o setup alterou (escopo, seção 15: reexecução sem duplicação e desinstalação limpa).
type Manifest struct {
	Version   int       `json:"version"`
	Product   string    `json:"product"`
	Options   Options   `json:"options"`
	UpdatedAt time.Time `json:"updated_at"`
	Changes   []Change  `json:"changes"`
}

func (m *Manifest) wrote(path string) bool {
	if m == nil {
		return false
	}
	return slices.ContainsFunc(m.Changes, func(c Change) bool { return c.Kind == "file" && c.Path == path })
}

func (m *Manifest) find(kind, key string) *Change {
	for i := range m.Changes {
		c := &m.Changes[i]
		if c.Kind == kind && (c.Path == key || c.Unit == key) {
			return c
		}
	}
	return nil
}

// LoadManifest lê o manifesto; ausente devolve nil sem erro.
func (s *System) LoadManifest() (*Manifest, error) {
	b, err := os.ReadFile(s.path(ManifestPath))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("manifesto %s ilegível: %w", ManifestPath, err)
	}
	return &m, nil
}

func (s *System) saveManifest(m *Manifest) error {
	m.Version, m.Product, m.UpdatedAt = 1, version.Version, s.now()
	b, _ := json.MarshalIndent(m, "", "  ")
	return s.writeFile(ManifestPath, append(b, '\n'), 0o600)
}

func (s *System) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *System) writeFile(p string, data []byte, perm os.FileMode) error {
	full := s.path(p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil { //nolint:gosec // diretórios de configuração do sistema
		return err
	}
	tmp := full + ".vigiahost-tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, full)
}

// backup copia o arquivo atual para BackupRoot/setup-AAAAMMDD-HHMMSS/<caminho>.
func (s *System) backup(p string) (string, error) {
	data, err := os.ReadFile(s.path(p)) //nolint:gosec // caminho do plano
	if err != nil {
		return "", err
	}
	dst := filepath.ToSlash(filepath.Join(BackupRoot, "setup-"+s.now().Format("20060102-150405"), p))
	return dst, s.writeFile(dst, data, 0o600)
}

// Apply executa o plano, registrando cada alteração antes de seguir para a próxima.
func (s *System) Apply(ctx context.Context, p Plan, prev *Manifest, out io.Writer) (*Manifest, error) {
	if len(p.Blockers) > 0 {
		return prev, errors.New("o plano tem impedimentos; resolva-os e rode o setup plan de novo")
	}
	m := prev
	if m == nil {
		m = &Manifest{}
	}
	m.Options = p.Options
	reload := false
	for _, a := range p.Actions {
		if a.Done {
			fmt.Fprintf(out, "✓ %s (já estava feito)\n", a.Description)
			continue
		}
		fmt.Fprintf(out, "→ %s\n", a.Description)
		switch a.Kind {
		case "file":
			if m.find("file", a.Path) == nil {
				c := Change{ID: a.ID, Kind: "file", Path: a.Path, At: s.now()}
				if _, err := os.Stat(s.path(a.Path)); err == nil {
					b, err := s.backup(a.Path)
					if err != nil {
						return m, fmt.Errorf("backup de %s: %w", a.Path, err)
					}
					c.Backup = b
				} else {
					c.Created = true
				}
				m.Changes = append(m.Changes, c)
				// O registro vem antes da escrita: se algo falhar no meio, a desinstalação ainda sabe o que desfazer.
				if err := s.saveManifest(m); err != nil {
					return m, err
				}
			}
			if err := s.writeFile(a.Path, a.Content, 0o644); err != nil {
				return m, err
			}
			reload = true
		case "remove-file":
			if err := s.revertFile(m.find("file", a.Path)); err != nil {
				return m, err
			}
			m.Changes = slices.DeleteFunc(m.Changes, func(c Change) bool { return c.Kind == "file" && c.Path == a.Path })
			reload = true
		case "service":
			if reload {
				if _, err := s.Systemctl(ctx, "daemon-reload"); err != nil {
					return m, fmt.Errorf("systemctl daemon-reload: %w", err)
				}
				reload = false
			}
			if m.find("service", a.Unit) == nil {
				st := p.Env.Services[a.Unit]
				m.Changes = append(m.Changes, Change{ID: a.ID, Kind: "service", Unit: a.Unit, At: s.now(),
					Prior: &Prior{Enabled: st.Enabled == "enabled", Active: st.Active == "active"}})
				if err := s.saveManifest(m); err != nil {
					return m, err
				}
			}
			if out, err := s.Systemctl(ctx, "enable", "--now", a.Unit); err != nil {
				return m, fmt.Errorf("systemctl enable --now %s: %w (%s)", a.Unit, err, out)
			}
		case "restart":
			if reload {
				_, _ = s.Systemctl(ctx, "daemon-reload")
				reload = false
			}
			if out, err := s.Systemctl(ctx, "restart", a.Unit); err != nil {
				return m, fmt.Errorf("systemctl restart %s: %w (%s)", a.Unit, err, out)
			}
		}
	}
	if reload {
		_, _ = s.Systemctl(ctx, "daemon-reload")
	}
	return m, s.saveManifest(m)
}

// revertFile devolve o arquivo ao estado anterior ao setup (apaga o criado ou restaura o backup).
func (s *System) revertFile(c *Change) error {
	if c == nil {
		return nil
	}
	if c.Created || c.Backup == "" {
		if err := os.Remove(s.path(c.Path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		_ = os.Remove(filepath.Dir(s.path(c.Path))) // o diretório .d criado pelo setup, se ficou vazio
		return nil
	}
	data, err := os.ReadFile(s.path(c.Backup))
	if err != nil {
		return fmt.Errorf("backup %s: %w", c.Backup, err)
	}
	return s.writeFile(c.Path, data, 0o644)
}

// Uninstall desfaz o que o manifesto registra, na ordem inversa. Com purge, apaga também os dados do produto.
func (s *System) Uninstall(ctx context.Context, purge bool, out io.Writer) error {
	m, err := s.LoadManifest()
	if err != nil {
		return err
	}
	if m == nil {
		fmt.Fprintln(out, "nenhum manifesto do setup: nada a desfazer além do pacote")
		m = &Manifest{}
	}
	var errs []error
	for i := len(m.Changes) - 1; i >= 0; i-- {
		c := m.Changes[i]
		switch c.Kind {
		case "service":
			if c.Prior != nil && c.Prior.Enabled && c.Prior.Active {
				fmt.Fprintf(out, "• %s já estava habilitado antes do setup: só parado\n", c.Unit)
			}
			fmt.Fprintf(out, "→ parar e desabilitar %s\n", c.Unit)
			if o, err := s.Systemctl(ctx, "disable", "--now", c.Unit); err != nil {
				errs = append(errs, fmt.Errorf("systemctl disable --now %s: %w (%s)", c.Unit, err, o))
			}
		case "file":
			fmt.Fprintf(out, "→ desfazer %s\n", c.Path)
			if err := s.revertFile(&c); err != nil {
				errs = append(errs, err)
			}
		}
	}
	_, _ = s.Systemctl(ctx, "daemon-reload")
	if purge {
		for _, d := range DataDirs {
			fmt.Fprintf(out, "→ apagar %s\n", d)
			if err := os.RemoveAll(s.path(d)); err != nil {
				errs = append(errs, err)
			}
		}
	} else if err := os.Remove(s.path(ManifestPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
