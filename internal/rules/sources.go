package rules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/controls"
	"github.com/guigallina27/vigiahost/internal/engines/yarax"
	"github.com/guigallina27/vigiahost/internal/fsperm"
)

// trusted confere dono e permissões (trocado nos testes, que não rodam como root).
var trusted = fsperm.RootOnly

// UserDir guarda as fontes locais de regras do administrador: um subdiretório por fonte, com arquivos .yar/.yara
// e, opcionalmente, source.json com descrição, licença, autor, endereço e versão. Só o root grava ali (o diretório
// fica em /etc, só leitura para as execuções).
const UserDir = "/etc/vigiahost/rules.d"

// StatusFile é o resultado da última compilação, no diretório das regras compiladas.
const StatusFile = "status.json"

// Origens de uma fonte.
const (
	OriginBuiltin = "builtin" // embarcada no produto, escrita pelo projeto
	OriginLocal   = "local"   // colocada pelo administrador em UserDir
)

// Estados de uma fonte na compilação.
const (
	StateOK       = "ok"
	StateError    = "error"    // não compilou; fica fora do conjunto
	StateDisabled = "disabled" // desativada pelo administrador
	StateRefused  = "refused"  // recusada antes de compilar (permissões, include, limites)
)

// Limites de uma fonte local (regras de terceiros são entrada não confiável, escopo 7.3).
const (
	maxSourceFiles = 500
	maxFileBytes   = 8 << 20
	maxSourceBytes = 64 << 20
	maxDepth       = 4
	maxErrorBytes  = 2048
)

// SourceNamePattern é o formato do nome de uma fonte (vira o namespace das regras e a "fonte" dos achados).
var SourceNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// Nomes que fontes locais não podem usar (embarcadas e motores).
var reservedNames = []string{NamespaceProduct, NamespaceControl, "lmd", "rfxn", "clamav", "clamav-unofficial", "yara-x", "inventory", "inspector"}

// SourceInfo descreve uma fonte de regras YARA como está agora no servidor.
type SourceInfo struct {
	Name        string    `json:"name"`
	Origin      string    `json:"origin"`
	Path        string    `json:"path,omitempty"`
	Mandatory   bool      `json:"mandatory,omitempty"`
	Description string    `json:"description,omitempty"`
	License     string    `json:"license,omitempty"`
	Author      string    `json:"author,omitempty"`
	URL         string    `json:"url,omitempty"`
	Version     string    `json:"version,omitempty"`
	Files       int       `json:"files"`
	Rules       int       `json:"rules"`
	Bytes       int64     `json:"bytes"`
	Hash        string    `json:"hash,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitzero"`
	// Problem explica por que a fonte é recusada antes de compilar.
	Problem string `json:"problem,omitempty"`
}

// SourceResult é o estado de uma fonte na última compilação.
type SourceResult struct {
	Name  string `json:"name"`
	Hash  string `json:"hash,omitempty"`
	State string `json:"state"`
	Error string `json:"error,omitempty"`
	Rules int    `json:"rules"`
}

// CompileStatus é gravado a cada compilação (execução ou pedido do administrador).
type CompileStatus struct {
	At         time.Time      `json:"at"`
	Trigger    string         `json:"trigger"` // scan, inspect, manual
	YRVersion  string         `json:"yr_version"`
	SetVersion string         `json:"set_version,omitempty"`
	OK         bool           `json:"ok"`
	Error      string         `json:"error,omitempty"`
	Disabled   []string       `json:"disabled,omitempty"`
	Sources    []SourceResult `json:"sources"`
	// SelfTest: o conjunto compilado detectou o controle positivo (só na compilação pedida pelo administrador).
	SelfTest *bool  `json:"selftest,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

var (
	yaraRuleDecl = regexp.MustCompile(`(?m)^\s*(?:(?:private|global)\s+)*rule\s+[A-Za-z_]`)
	includeDecl  = regexp.MustCompile(`(?m)^\s*include\s+"`)
)

// CountRules conta as declarações de regra (aproximado: não interpreta comentários de bloco).
func CountRules(data []byte) int { return len(yaraRuleDecl.FindAll(data, -1)) }

// Builtin descreve as fontes embarcadas (controle positivo e regras do projeto).
func Builtin() []SourceInfo {
	control := SourceInfo{Name: NamespaceControl, Origin: OriginBuiltin, Mandatory: true,
		Description: "Controle positivo inerte do autoteste", License: "GPL-3.0-only", Author: "VigiaHost",
		Files: 1, Rules: CountRules([]byte(controls.YARARule)), Bytes: int64(len(controls.YARARule))}
	h := sha256.New()
	h.Write([]byte(controls.YARARule))
	control.Hash = hex.EncodeToString(h.Sum(nil))

	product := SourceInfo{Name: NamespaceProduct, Origin: OriginBuiltin,
		Description: "Regras escritas pelo projeto: scripts maliciosos, webshells, mineradores e binários empacotados",
		License:     "GPL-3.0-only", Author: "VigiaHost"}
	names, _ := fs.Glob(builtin, "vigiahost/*.yar")
	sort.Strings(names)
	h = sha256.New()
	for _, n := range names {
		data, err := builtin.ReadFile(n)
		if err != nil {
			continue
		}
		product.Files++
		product.Bytes += int64(len(data))
		product.Rules += CountRules(data)
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", filepath.Base(n), len(data))
		h.Write(data)
	}
	product.Hash = hex.EncodeToString(h.Sum(nil))
	return []SourceInfo{control, product}
}

// sourceMeta é o source.json opcional de uma fonte local.
type sourceMeta struct {
	Description string `json:"description"`
	License     string `json:"license"`
	Author      string `json:"author"`
	URL         string `json:"url"`
	Version     string `json:"version"`
}

// Inspect lista as fontes: as embarcadas e as locais de userDir, com hash, contagem de regras e problemas.
// Só lê; serve para a tela e para preparar a compilação.
func Inspect(userDir string) []SourceInfo {
	out := Builtin()
	if userDir == "" {
		return out
	}
	ents, err := os.ReadDir(userDir)
	if err != nil {
		return out
	}
	for _, e := range ents {
		if !e.IsDir() && e.Type()&fs.ModeSymlink == 0 {
			continue // arquivos soltos (README) não são fontes
		}
		info, _ := inspectLocal(userDir, e.Name(), "")
		out = append(out, info)
	}
	return out
}

// inspectLocal lê uma fonte local; com copyTo, copia os arquivos lidos (o conjunto compilado é exatamente o que foi
// conferido, mesmo que o administrador altere a fonte durante a compilação).
func inspectLocal(userDir, name, copyTo string) (SourceInfo, error) {
	dir := filepath.Join(userDir, name)
	info := SourceInfo{Name: name, Origin: OriginLocal, Path: dir}
	fail := func(format string, args ...any) (SourceInfo, error) {
		info.Problem = fmt.Sprintf(format, args...)
		return info, errors.New(info.Problem)
	}
	if !SourceNamePattern.MatchString(name) {
		return fail("nome inválido: use de 1 a 32 letras minúsculas, números, - ou _")
	}
	if slices.Contains(reservedNames, name) {
		return fail("nome reservado pelo produto")
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return fail("ilegível: %v", err)
	}
	if !st.IsDir() {
		return fail("precisa ser um diretório (links simbólicos não são seguidos)")
	}
	if !trusted(st) {
		return fail("o diretório precisa ser do root e sem escrita para outros usuários")
	}
	if meta, err := os.ReadFile(filepath.Join(dir, "source.json")); err == nil { //nolint:gosec // fonte local do root
		var m sourceMeta
		dec := json.NewDecoder(bytes.NewReader(meta))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil {
			return fail("source.json inválido: %v", err)
		}
		if m.URL != "" && !strings.HasPrefix(m.URL, "https://") {
			return fail("source.json: url precisa começar com https://")
		}
		info.Description, info.License, info.Author = clip(m.Description, 256), clip(m.License, 64), clip(m.Author, 128)
		info.URL, info.Version = clip(m.URL, 512), clip(m.Version, 64)
	}
	if copyTo != "" {
		if err := os.MkdirAll(copyTo, 0o700); err != nil {
			return info, err
		}
	}
	h := sha256.New()
	var files []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			if strings.Count(rel, string(filepath.Separator)) >= maxDepth {
				return fmt.Errorf("subdiretórios demais em %s", rel)
			}
			if p != dir {
				fi, err := d.Info()
				if err != nil || !trusted(fi) {
					return fmt.Errorf("%s precisa ser do root e sem escrita para outros usuários", rel)
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yar" && ext != ".yara" {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
			return fmt.Errorf("%s não é arquivo comum (links simbólicos não são seguidos)", rel)
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return fail("%v", err)
	}
	if len(files) == 0 {
		return fail("nenhum arquivo .yar ou .yara")
	}
	if len(files) > maxSourceFiles {
		return fail("arquivos demais (%d; máximo %d)", len(files), maxSourceFiles)
	}
	sort.Strings(files)
	for _, rel := range files {
		p := filepath.Join(dir, rel)
		fi, err := os.Lstat(p)
		if err != nil {
			return fail("%s: %v", rel, err)
		}
		if !fi.Mode().IsRegular() || !trusted(fi) {
			return fail("%s precisa ser arquivo comum do root, sem escrita para outros usuários", rel)
		}
		if fi.Size() > maxFileBytes {
			return fail("%s maior que %d MiB", rel, maxFileBytes>>20)
		}
		data, err := os.ReadFile(p) //nolint:gosec // fonte local do root, conferida acima
		if err != nil {
			return fail("%s: %v", rel, err)
		}
		info.Bytes += int64(len(data))
		if info.Bytes > maxSourceBytes {
			return fail("fonte maior que %d MiB", maxSourceBytes>>20)
		}
		// include leria arquivos fora da fonte (e o erro de compilação mostraria o conteúdo): não é aceito.
		if includeDecl.Match(data) {
			return fail("%s usa include, que não é aceito (junte as regras na própria fonte)", rel)
		}
		info.Files++
		info.Rules += CountRules(data)
		if fi.ModTime().After(info.UpdatedAt) {
			info.UpdatedAt = fi.ModTime().UTC()
		}
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", filepath.ToSlash(rel), len(data))
		h.Write(data)
		if copyTo != "" {
			// Cópia plana com o índice na frente: sem colisão de nomes e com o nome original reconhecível nos erros.
			dst := filepath.Join(copyTo, fmt.Sprintf("%04d-%s", info.Files, filepath.Base(rel)))
			if err := os.WriteFile(dst, data, 0o600); err != nil { //nolint:gosec // destino no diretório de trabalho, nome só com o índice e a base do arquivo
				return info, err
			}
		}
	}
	info.Hash = hex.EncodeToString(h.Sum(nil))
	return info, nil
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// PrepareOptions ajusta a preparação do conjunto.
type PrepareOptions struct {
	UserDir  string
	Disabled []string
	Trigger  string
}

// Prepare monta e compila o conjunto: embarcadas (o controle positivo sempre), mais as fontes locais ativas que
// passarem na conferência e compilarem sozinhas. Fonte com erro fica fora (com o motivo no status) em vez de
// derrubar o YARA inteiro. Grava dir/status.json e devolve o arquivo compilado.
func Prepare(ctx context.Context, yr, yrVersion, dir string, opts PrepareOptions) (Set, string, CompileStatus, error) {
	st := CompileStatus{At: time.Now().UTC(), Trigger: opts.Trigger, YRVersion: yrVersion, Disabled: opts.Disabled}
	prev, _ := ReadStatus(dir)
	disabled := func(n string) bool { return slices.Contains(opts.Disabled, n) }
	srcDir := filepath.Join(dir, "src")
	if err := os.RemoveAll(filepath.Join(srcDir, "local")); err != nil {
		return Set{}, "", st, err
	}
	var extra []yarax.Source
	for _, b := range Builtin() {
		r := SourceResult{Name: b.Name, Hash: b.Hash, State: StateOK, Rules: b.Rules}
		if !b.Mandatory && disabled(b.Name) {
			r.State = StateDisabled
		}
		st.Sources = append(st.Sources, r)
	}
	if opts.UserDir != "" {
		ents, _ := os.ReadDir(opts.UserDir)
		for _, e := range ents {
			if !e.IsDir() && e.Type()&fs.ModeSymlink == 0 {
				continue
			}
			name := e.Name()
			if disabled(name) {
				st.Sources = append(st.Sources, SourceResult{Name: name, State: StateDisabled})
				continue
			}
			copyTo := filepath.Join(srcDir, "local", name)
			info, err := inspectLocal(opts.UserDir, name, copyTo)
			r := SourceResult{Name: name, Hash: info.Hash, Rules: info.Rules}
			if err != nil {
				r.State, r.Error = StateRefused, clip(err.Error(), maxErrorBytes)
				st.Sources = append(st.Sources, r)
				continue
			}
			src := yarax.Source{Namespace: name, Path: copyTo}
			if p := prev.find(name); p != nil && p.Hash == info.Hash && p.State == StateOK && prev.YRVersion == yrVersion {
				r.State = StateOK // já compilou sozinha com o mesmo conteúdo e a mesma versão do yr
			} else if err := yarax.Compile(ctx, yr, []yarax.Source{src}, filepath.Join(dir, ".valida-"+name+".yarc")); err != nil {
				r.State, r.Error = StateError, clip(err.Error(), maxErrorBytes)
			} else {
				r.State = StateOK
			}
			_ = os.Remove(filepath.Join(dir, ".valida-"+name+".yarc"))
			if r.State == StateOK {
				extra = append(extra, src)
			}
			st.Sources = append(st.Sources, r)
		}
	}
	set, err := materialize(srcDir, !disabled(NamespaceProduct), extra)
	if err == nil {
		st.SetVersion = set.Version
		var out string
		out, err = Compiled(ctx, yr, yrVersion, dir, set)
		if err == nil {
			st.OK = true
			return set, out, st, WriteStatus(dir, st)
		}
	}
	st.Error = clip(err.Error(), maxErrorBytes)
	_ = WriteStatus(dir, st)
	return set, "", st, err
}

func (s *CompileStatus) find(name string) *SourceResult {
	if s == nil {
		return nil
	}
	for i := range s.Sources {
		if s.Sources[i].Name == name {
			return &s.Sources[i]
		}
	}
	return nil
}

// ReadStatus lê o resultado da última compilação (nil sem compilação registrada).
func ReadStatus(dir string) (*CompileStatus, error) {
	data, err := os.ReadFile(filepath.Join(dir, StatusFile)) //nolint:gosec // diretório de estado do executor
	if err != nil {
		return nil, err
	}
	var st CompileStatus
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// WriteStatus grava o resultado com troca atômica.
func WriteStatus(dir string, st CompileStatus) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".status-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, StatusFile))
}

// ValidDisabled confere a lista de fontes desativadas vinda do core: nomes válidos, sem repetição, no máximo 64, e
// nunca o controle positivo.
func ValidDisabled(names []string) error {
	if len(names) > 64 {
		return errors.New("fontes desativadas demais")
	}
	seen := map[string]bool{}
	for _, n := range names {
		if !SourceNamePattern.MatchString(n) {
			return fmt.Errorf("fonte de regras inválida: %q", n)
		}
		if n == NamespaceControl {
			return errors.New("o controle positivo não pode ser desativado")
		}
		if seen[n] {
			return fmt.Errorf("fonte repetida: %q", n)
		}
		seen[n] = true
	}
	return nil
}
