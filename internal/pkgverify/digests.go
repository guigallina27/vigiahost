package pkgverify

import (
	"bufio"
	"context"
	"crypto/md5"  //nolint:gosec // o dpkg só registra MD5; serve para conferir com o banco, não como garantia criptográfica
	"crypto/sha1" //nolint:gosec // idem, pacotes RPM antigos
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Situação de um arquivo conferido contra o pacote.
const (
	StatusMatch      = "match"      // conteúdo igual ao registrado no pacote
	StatusMismatch   = "mismatch"   // conteúdo diferente
	StatusNotOwned   = "not_owned"  // nenhum pacote registra o arquivo
	StatusMissing    = "missing"    // registrado, mas ausente do disco
	StatusNoDigest   = "no_digest"  // registrado sem resumo (diretório, link, arquivo fantasma)
	StatusUnreadable = "unreadable" // não deu para ler o arquivo
)

// FileCheck é a resposta de "este arquivo pertence a qual pacote e confere com ele?".
type FileCheck struct {
	Path     string    `json:"path"`
	Status   string    `json:"status"`
	Packages []Package `json:"packages,omitempty"`
	Config   bool      `json:"config,omitempty"`
	// Algo, Expected e Actual: resumo registrado no pacote e o calculado agora, no mesmo algoritmo.
	Algo     string `json:"algo,omitempty"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	// SHA256 do conteúdo atual (para cruzar com os motores e com o inventário).
	SHA256 string `json:"sha256,omitempty"`
	// Signature é a assinatura do pacote dono (RPM): signed, unknown_key ou unsigned. No dpkg a assinatura é do
	// repositório e fica no relatório de assinaturas.
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

type fileDigest struct {
	algo   string
	digest string
	config bool
}

// Algoritmos do FILEDIGESTALGO do RPM (rpmpgp.h).
var rpmDigestAlgos = map[string]string{"1": "md5", "2": "sha1", "8": "sha256", "9": "sha384", "10": "sha512", "11": "sha224"}

func newHash(algo string) hash.Hash {
	switch algo {
	case "md5":
		return md5.New() //nolint:gosec // conferência com o banco do dpkg
	case "sha1":
		return sha1.New() //nolint:gosec // idem
	case "sha256":
		return sha256.New()
	case "sha224":
		return sha256.New224()
	case "sha384":
		return sha512.New384()
	case "sha512":
		return sha512.New()
	}
	return nil
}

// maxHashBytes limita o arquivo lido para conferir o resumo.
const maxHashBytes = 4 << 30

// CheckFiles confere cada caminho contra o pacote dono: resumo registrado × conteúdo atual.
func (v *Verifier) CheckFiles(ctx context.Context, paths []string) (map[string]FileCheck, error) {
	owners, err := v.Owners(ctx, paths)
	if err != nil {
		return nil, err
	}
	var pkgs []Package
	seen := map[Package]bool{}
	for _, list := range owners {
		for _, p := range list {
			if !seen[p] {
				seen[p] = true
				pkgs = append(pkgs, p)
			}
		}
	}
	if err := v.loadDigests(ctx, pkgs); err != nil {
		return nil, err
	}
	var sigs map[string]string
	if v.Manager == RPM {
		if rep, err := v.Signatures(ctx); err == nil {
			sigs = rep.byPackage
		}
	}
	out := make(map[string]FileCheck, len(paths))
	for _, p := range paths {
		fc := FileCheck{Path: p, Packages: owners[p]}
		if len(fc.Packages) == 0 {
			fc.Status = StatusNotOwned
			fc.SHA256, _ = hashPath(v.onDisk(p))
			out[p] = fc
			continue
		}
		if sigs != nil {
			fc.Signature = sigs[fc.Packages[0].String()]
		}
		var expected []fileDigest
		v.mu.Lock()
		for _, pk := range fc.Packages {
			for _, alt := range usrMergeAlternates(p) {
				if d, ok := v.digests[pk.String()][alt]; ok {
					expected = append(expected, d)
					break
				}
			}
		}
		v.mu.Unlock()
		for _, d := range expected {
			fc.Config = fc.Config || d.config
		}
		st, err := os.Lstat(v.onDisk(p))
		switch {
		case err != nil && errors.Is(err, os.ErrNotExist):
			fc.Status = StatusMissing
		case err != nil:
			fc.Status, fc.Error = StatusUnreadable, err.Error()
		case !st.Mode().IsRegular() || len(expected) == 0 || expected[0].digest == "":
			fc.Status = StatusNoDigest
			if st.Mode().IsRegular() {
				fc.SHA256, _ = hashPath(v.onDisk(p))
			}
		default:
			fc.Algo, fc.Expected = expected[0].algo, expected[0].digest
			sum, actual, err := hashPathPair(v.onDisk(p), fc.Algo)
			if err != nil {
				fc.Status, fc.Error = StatusUnreadable, err.Error()
				break
			}
			fc.SHA256, fc.Actual, fc.Status = sum, actual, StatusMismatch
			for _, d := range expected {
				if d.algo == fc.Algo && strings.EqualFold(d.digest, actual) {
					fc.Status, fc.Expected = StatusMatch, d.digest
					break
				}
			}
		}
		out[p] = fc
	}
	return out, ctx.Err()
}

// hashPath devolve o SHA-256 de um arquivo regular.
func hashPath(p string) (string, error) {
	sum, _, err := hashPathPair(p, "")
	return sum, err
}

// hashPathPair calcula o SHA-256 e, se pedido, outro algoritmo numa leitura só. Não segue link no último
// componente e só lê arquivo regular.
func hashPathPair(p, algo string) (sha string, other string, err error) {
	f, err := os.OpenFile(p, os.O_RDONLY|openNoFollow, 0) //nolint:gosec // caminho do banco de pacotes
	if err != nil {
		return "", "", err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return "", "", err
	}
	if !st.Mode().IsRegular() {
		return "", "", errors.New("não é arquivo regular")
	}
	h := sha256.New()
	w := io.Writer(h)
	var o hash.Hash
	if algo != "" && algo != "sha256" {
		if o = newHash(algo); o == nil {
			return "", "", errors.New("algoritmo de resumo desconhecido: " + algo)
		}
		w = io.MultiWriter(h, o)
	}
	if _, err := io.Copy(w, io.LimitReader(f, maxHashBytes)); err != nil {
		return "", "", err
	}
	sha = hex.EncodeToString(h.Sum(nil))
	switch {
	case o != nil:
		other = hex.EncodeToString(o.Sum(nil))
	case algo == "sha256":
		other = sha
	}
	return sha, other, nil
}

// loadDigests carrega os resumos registrados dos pacotes ainda fora do cache.
func (v *Verifier) loadDigests(ctx context.Context, pkgs []Package) error {
	v.mu.Lock()
	if v.digests == nil {
		v.digests = map[string]map[string]fileDigest{}
	}
	var todo []Package
	for _, p := range pkgs {
		if _, ok := v.digests[p.String()]; !ok {
			todo = append(todo, p)
		}
	}
	v.mu.Unlock()
	if len(todo) == 0 {
		return nil
	}
	switch v.Manager {
	case RPM:
		for i := 0; i < len(todo); i += 200 {
			if err := v.rpmDigests(ctx, todo[i:min(i+200, len(todo))]); err != nil {
				return err
			}
		}
	case DPKG:
		if err := v.loadDpkgStatus(); err != nil {
			return err
		}
		for _, p := range todo {
			m := v.dpkgDigests(p)
			v.mu.Lock()
			v.digests[p.String()] = m
			v.mu.Unlock()
		}
	}
	return nil
}

// rpmDigestFormat lista, por arquivo: pacote, algoritmo, caminho, resumo e marcas (bit 1 = configuração).
const rpmDigestFormat = `[%{=NAME}\t%{=EPOCHNUM}\t%{=VERSION}\t%{=RELEASE}\t%{=ARCH}\t%{=FILEDIGESTALGO}\t%{FILENAMES}\t%{FILEDIGESTS}\t%{FILEFLAGS}\n]`

func (v *Verifier) rpmDigests(ctx context.Context, pkgs []Package) error {
	args := []string{"-q", "--qf", rpmDigestFormat, "--"}
	for _, p := range pkgs {
		args = append(args, p.String())
	}
	got := map[string]map[string]fileDigest{}
	w := &lineWriter{fn: func(l string) {
		pk, path, d, ok := parseRPMDigestLine(l)
		if !ok {
			return
		}
		key := pk.String()
		if got[key] == nil {
			got[key] = map[string]fileDigest{}
		}
		got[key][path] = d
	}}
	stderr, code, err := v.runner().Run(ctx, w, rpmBin, args...)
	if err != nil {
		return err
	}
	if code != 0 && len(got) == 0 {
		return describeExit(rpmBin, code, stderr)
	}
	v.mu.Lock()
	for _, p := range pkgs {
		v.digests[p.String()] = got[p.String()]
	}
	v.mu.Unlock()
	return nil
}

// parseRPMDigestLine lê uma linha de rpmDigestFormat.
func parseRPMDigestLine(l string) (Package, string, fileDigest, bool) {
	f := strings.Split(l, "\t")
	if len(f) != 9 || !strings.HasPrefix(f[6], "/") {
		return Package{}, "", fileDigest{}, false
	}
	flags, _ := strconv.ParseUint(f[8], 10, 32)
	algo := rpmDigestAlgos[f[5]]
	if algo == "" {
		algo = "md5" // pacotes antigos sem a marca usam MD5
	}
	d := fileDigest{algo: algo, digest: strings.ToLower(f[7]), config: flags&1 != 0}
	return rpmPackage(f[0], f[1], f[2], f[3], f[4]), f[6], d, true
}

// dpkgDigests lê o .md5sums do pacote (caminhos relativos) e as configurações dele registradas no status.
func (v *Verifier) dpkgDigests(p Package) map[string]fileDigest {
	m := map[string]fileDigest{}
	for _, name := range []string{p.Name + ":" + p.Arch, p.Name} {
		f, err := os.Open(filepath.Join(v.infoDir(), name+".md5sums")) //nolint:gosec // banco do dpkg
		if err != nil {
			continue
		}
		for path, sum := range ParseMD5Sums(f) {
			m[path] = fileDigest{algo: "md5", digest: sum}
		}
		_ = f.Close()
		break
	}
	v.mu.Lock()
	conf := v.conffiles[p.Name+":"+p.Arch]
	v.mu.Unlock()
	for path, sum := range conf {
		m[path] = fileDigest{algo: "md5", digest: sum, config: true}
	}
	return m
}

// ParseMD5Sums lê um arquivo .md5sums do dpkg ("<md5>  caminho/relativo").
func ParseMD5Sums(r io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		sum, path, ok := strings.Cut(sc.Text(), "  ")
		if !ok || len(sum) != 32 || path == "" {
			continue
		}
		out["/"+strings.TrimPrefix(path, "/")] = strings.ToLower(sum)
	}
	return out
}
