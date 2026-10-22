package pkgverify

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// rpmPkgFormat é o formato de consulta de um pacote (nome, época, versão, lançamento, arquitetura).
const rpmPkgFormat = `%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n`

// rpmBatch é quantos caminhos vão por chamada do "rpm -qf".
const rpmBatch = 400

// Owners devolve os pacotes donos de cada caminho (lista vazia = nenhum pacote). Resultados ficam em cache.
func (v *Verifier) Owners(ctx context.Context, paths []string) (map[string][]Package, error) {
	if err := v.check(); err != nil {
		return nil, err
	}
	out := make(map[string][]Package, len(paths))
	var todo []string
	seen := map[string]bool{}
	v.mu.Lock()
	if v.owners == nil {
		v.owners = map[string][]Package{}
	}
	for _, p := range paths {
		if seen[p] {
			continue
		}
		seen[p] = true
		if o, ok := v.owners[p]; ok {
			out[p] = o
		} else if strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "\n\x00") {
			todo = append(todo, p)
		} else {
			out[p] = nil
		}
	}
	v.mu.Unlock()
	if len(todo) == 0 {
		return out, nil
	}
	var found map[string][]Package
	var err error
	switch v.Manager {
	case RPM:
		found, err = v.rpmOwners(ctx, todo)
	case DPKG:
		found, err = v.dpkgOwners(todo)
	}
	if err != nil {
		return out, err
	}
	v.mu.Lock()
	for _, p := range todo {
		v.owners[p] = found[p]
		out[p] = found[p]
	}
	v.mu.Unlock()
	return out, nil
}

// Owner devolve o primeiro dono do caminho.
func (v *Verifier) Owner(ctx context.Context, path string) (Package, bool, error) {
	m, err := v.Owners(ctx, []string{path})
	if err != nil || len(m[path]) == 0 {
		return Package{}, false, err
	}
	return m[path][0], true, nil
}

// ParseRPMPackageLine lê uma linha no formato rpmPkgFormat.
func ParseRPMPackageLine(line string) (Package, bool) {
	f := strings.Split(line, "\t")
	if len(f) != 5 || f[0] == "" {
		return Package{}, false
	}
	return rpmPackage(f[0], f[1], f[2], f[3], f[4]), true
}

func rpmPackage(name, epoch, ver, rel, arch string) Package {
	v := ver + "-" + rel
	if epoch != "" && epoch != "0" && epoch != "(none)" {
		v = epoch + ":" + v
	}
	if arch == "(none)" {
		arch = ""
	}
	return Package{Name: name, Version: v, Arch: arch}
}

// rpmOwners consulta os caminhos existentes pelo "rpm -qf" em lotes e os que não existem mais (arquivo apagado)
// pela lista completa de arquivos do banco, que não exige o arquivo no disco.
func (v *Verifier) rpmOwners(ctx context.Context, paths []string) (map[string][]Package, error) {
	out := map[string][]Package{}
	var existing, gone []string
	for _, p := range paths {
		if _, err := os.Lstat(v.onDisk(p)); err == nil {
			existing = append(existing, p)
		} else {
			gone = append(gone, p)
		}
	}
	for i := 0; i < len(existing); i += rpmBatch {
		if err := v.rpmQueryFiles(ctx, existing[i:min(i+rpmBatch, len(existing))], out); err != nil {
			return out, err
		}
	}
	if len(gone) > 0 {
		if err := v.rpmOwnersFromIndex(ctx, gone, out); err != nil {
			return out, err
		}
	}
	return out, nil
}

// rpmQueryFiles roda "rpm -qf" num lote. Arquivo de vários pacotes (multilib) gera mais de uma linha e desalinha a
// saída: nesse caso o lote é dividido ao meio até cada caminho ficar sozinho.
func (v *Verifier) rpmQueryFiles(ctx context.Context, batch []string, out map[string][]Package) error {
	args := append([]string{"-qf", "--qf", rpmPkgFormat, "--"}, batch...)
	raw, stderr, code, err := run(ctx, v.runner(), 16<<20, rpmBin, args...)
	if err != nil {
		return err
	}
	lines := splitLines(raw)
	if len(lines) == 0 && code != 0 {
		return describeExit(rpmBin, code, stderr)
	}
	if len(batch) == 1 {
		for _, l := range lines {
			if p, ok := ParseRPMPackageLine(l); ok {
				out[batch[0]] = appendPkg(out[batch[0]], p)
			}
		}
		if _, ok := out[batch[0]]; !ok {
			out[batch[0]] = nil
		}
		return nil
	}
	if len(lines) != len(batch) {
		mid := len(batch) / 2
		if err := v.rpmQueryFiles(ctx, batch[:mid], out); err != nil {
			return err
		}
		return v.rpmQueryFiles(ctx, batch[mid:], out)
	}
	for i, l := range lines {
		if p, ok := ParseRPMPackageLine(l); ok {
			out[batch[i]] = appendPkg(out[batch[i]], p)
		} else if _, ok := out[batch[i]]; !ok {
			out[batch[i]] = nil // "file ... is not owned by any package"
		}
	}
	return nil
}

func appendPkg(list []Package, p Package) []Package {
	for _, x := range list {
		if x == p {
			return list
		}
	}
	return append(list, p)
}

func splitLines(b []byte) []string {
	s := strings.TrimRight(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// lineWriter entrega cada linha completa a fn sem guardar a saída inteira.
type lineWriter struct {
	partial []byte
	fn      func(string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if len(w.partial)+len(p) > 1<<20 {
				w.partial = w.partial[:0] // linha absurda: descarta
			} else {
				w.partial = append(w.partial, p...)
			}
			break
		}
		w.partial = append(w.partial, p[:i]...)
		w.fn(string(w.partial))
		w.partial = w.partial[:0]
		p = p[i+1:]
	}
	return n, nil
}

// wantSet mapeia cada forma equivalente do caminho (/usr unificado) para os caminhos pedidos.
func wantSet(paths []string) map[string][]string {
	want := map[string][]string{}
	for _, p := range paths {
		for _, alt := range usrMergeAlternates(p) {
			want[alt] = append(want[alt], p)
		}
	}
	return want
}

// rpmOwnersFromIndex percorre a lista de arquivos de todos os pacotes e guarda só os pedidos.
func (v *Verifier) rpmOwnersFromIndex(ctx context.Context, paths []string, out map[string][]Package) error {
	want := wantSet(paths)
	w := &lineWriter{fn: func(l string) {
		file, rest, ok := strings.Cut(l, "\t")
		if !ok {
			return
		}
		origs, ok := want[file]
		if !ok {
			return
		}
		if p, ok := ParseRPMPackageLine(rest); ok {
			for _, o := range origs {
				out[o] = appendPkg(out[o], p)
			}
		}
	}}
	stderr, code, err := v.runner().Run(ctx, w, rpmBin, "-qa", "--qf",
		`[%{FILENAMES}\t%{=NAME}\t%{=EPOCHNUM}\t%{=VERSION}\t%{=RELEASE}\t%{=ARCH}\n]`)
	if err != nil {
		return err
	}
	if code != 0 {
		return describeExit(rpmBin, code, stderr)
	}
	for _, p := range paths {
		if _, ok := out[p]; !ok {
			out[p] = nil
		}
	}
	return nil
}

// --- dpkg ---

func (v *Verifier) infoDir() string { return filepath.Join(v.root(), "var", "lib", "dpkg", "info") }

// dpkgOwners lê os arquivos .list do banco do dpkg (sem subprocesso) e guarda só os caminhos pedidos.
func (v *Verifier) dpkgOwners(paths []string) (map[string][]Package, error) {
	if err := v.loadDpkgStatus(); err != nil {
		return nil, err
	}
	want := wantSet(paths)
	out := map[string][]Package{}
	ents, err := os.ReadDir(v.infoDir())
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".list")
		if !ok || e.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(v.infoDir(), e.Name())) //nolint:gosec // banco do dpkg
		if err != nil {
			continue
		}
		pkg := v.dpkgPackage(name)
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			for _, o := range want[sc.Text()] {
				out[o] = appendPkg(out[o], pkg)
			}
		}
		_ = f.Close()
	}
	for _, p := range paths {
		if _, ok := out[p]; !ok {
			out[p] = nil
		}
	}
	return out, nil
}

// dpkgPackage converte o nome do arquivo do banco ("libc6:amd64") no pacote instalado.
func (v *Verifier) dpkgPackage(key string) Package {
	v.mu.Lock()
	defer v.mu.Unlock()
	if p, ok := v.dpkgPkgs[key]; ok {
		return p
	}
	name, arch, _ := strings.Cut(key, ":")
	if p, ok := v.dpkgPkgs[name]; ok && (arch == "" || p.Arch == arch) {
		return p
	}
	return Package{Name: name, Arch: arch}
}

// DpkgStatus é um pacote lido do /var/lib/dpkg/status.
type DpkgStatus struct {
	Package   Package
	Installed bool
	// Conffiles: caminho → md5 registrado na instalação.
	Conffiles map[string]string
}

// ParseDpkgStatus lê o arquivo de status do dpkg (estrofes separadas por linha vazia).
func ParseDpkgStatus(r io.Reader) ([]DpkgStatus, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var out []DpkgStatus
	cur := DpkgStatus{}
	field := ""
	flush := func() {
		if cur.Package.Name != "" {
			out = append(out, cur)
		}
		cur, field = DpkgStatus{}, ""
	}
	for sc.Scan() {
		l := sc.Text()
		if l == "" {
			flush()
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			if field == "Conffiles" {
				f := strings.Fields(l)
				if len(f) >= 2 && strings.HasPrefix(f[0], "/") {
					if cur.Conffiles == nil {
						cur.Conffiles = map[string]string{}
					}
					cur.Conffiles[f[0]] = f[1]
				}
			}
			continue
		}
		k, val, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		field, val = k, strings.TrimSpace(val)
		switch k {
		case "Package":
			cur.Package.Name = val
		case "Version":
			cur.Package.Version = val
		case "Architecture":
			cur.Package.Arch = val
		case "Status":
			f := strings.Fields(val)
			cur.Installed = len(f) == 3 && (f[2] == "installed" || f[2] == "half-configured" || f[2] == "unpacked")
		}
	}
	flush()
	return out, sc.Err()
}

func (v *Verifier) loadDpkgStatus() error {
	v.mu.Lock()
	loaded := v.dpkgPkgs != nil
	v.mu.Unlock()
	if loaded {
		return nil
	}
	f, err := os.Open(filepath.Join(v.root(), "var", "lib", "dpkg", "status")) //nolint:gosec // banco do dpkg
	if err != nil {
		return fmt.Errorf("status do dpkg: %w", err)
	}
	defer func() { _ = f.Close() }()
	list, err := ParseDpkgStatus(f)
	if err != nil {
		return fmt.Errorf("status do dpkg: %w", err)
	}
	pkgs := map[string]Package{}
	conf := map[string]map[string]string{}
	sort.SliceStable(list, func(i, j int) bool { return list[i].Package.Name < list[j].Package.Name })
	for _, s := range list {
		if !s.Installed {
			continue
		}
		key := s.Package.Name + ":" + s.Package.Arch
		pkgs[key] = s.Package
		if _, ok := pkgs[s.Package.Name]; !ok {
			pkgs[s.Package.Name] = s.Package
		}
		if len(s.Conffiles) > 0 {
			conf[key] = s.Conffiles
		}
	}
	v.mu.Lock()
	v.dpkgPkgs, v.conffiles = pkgs, conf
	v.mu.Unlock()
	return nil
}

// PackageCount devolve quantos pacotes estão instalados (0 se não der para saber).
func (v *Verifier) PackageCount(ctx context.Context) int {
	switch v.Manager {
	case RPM:
		out, _, code, err := run(ctx, v.runner(), 16<<20, rpmBin, "-qa", "--qf", "%{NAME}\n")
		if err != nil || code != 0 {
			return 0
		}
		n := 0
		for _, l := range splitLines(out) {
			if l != "gpg-pubkey" {
				n++
			}
		}
		return n
	case DPKG:
		if v.loadDpkgStatus() != nil {
			return 0
		}
		v.mu.Lock()
		defer v.mu.Unlock()
		n := 0
		for k := range v.dpkgPkgs {
			if strings.Contains(k, ":") {
				n++
			}
		}
		return n
	}
	return 0
}
