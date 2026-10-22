package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type benignPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

// Limite de bytes extraídos por pacote: protege contra arquivo compactado que explode ao descompactar.
const maxExtracted = 2 << 30

func runBenign(args []string) error {
	fs := flag.NewFlagSet("benigno", flag.ExitOnError)
	out := outFlag(fs)
	list := fs.String("lista", "test/corpus/benign.json", "lista de pacotes com URL e SHA-256")
	cache := fs.String("cache", "/var/cache/vigiahost-corpus", "onde guardar os downloads conferidos")
	_ = fs.Parse(args)
	if err := prepareOut(*out); err != nil {
		return err
	}
	raw, err := os.ReadFile(*list)
	if err != nil {
		return err
	}
	var cfg struct {
		Packages []benignPackage `json:"packages"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	if err := os.MkdirAll(*cache, 0o755); err != nil {
		return err
	}
	m := Manifest{Kind: "benigno", Summary: map[string]any{}}
	for _, p := range cfg.Packages {
		archive, err := fetchVerified(*cache, p)
		if err != nil {
			return fmt.Errorf("%s %s: %w", p.Name, p.Version, err)
		}
		dest := filepath.Join(*out, p.Name+"-"+p.Version)
		files, skipped, err := extract(archive, dest)
		if err != nil {
			return fmt.Errorf("%s %s: %w", p.Name, p.Version, err)
		}
		m.Summary[p.Name+"-"+p.Version] = map[string]int{"arquivos": files, "ignorados": skipped}
		// Corpus benigno: nada aqui deve gerar achado; cada achado é um falso positivo a analisar.
		m.Entries = append(m.Entries, Entry{Path: p.Name + "-" + p.Version, Type: "dir", Size: p.Size, SHA256: p.SHA256,
			Note: fmt.Sprintf("%s %s oficial (%s); nenhum arquivo deve ser acusado", p.Name, p.Version, p.URL)})
	}
	return writeManifest(*out, m)
}

// fetchVerified baixa (ou reaproveita do cache) e só devolve o arquivo se o SHA-256 bater.
func fetchVerified(cache string, p benignPackage) (string, error) {
	dst := filepath.Join(cache, path.Base(p.URL))
	if ok, _ := hasSHA256(dst, p.SHA256); ok {
		return dst, nil
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(p.URL) //nolint:noctx // ferramenta de linha de comando, sem contexto de requisição
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp(cache, ".download-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, p.Size+1)); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != p.SHA256 {
		return "", fmt.Errorf("SHA-256 não confere: esperado %s, obtido %s", p.SHA256, got)
	}
	return dst, os.Rename(tmp.Name(), dst)
}

func hasSHA256(file, want string) (bool, error) {
	f, err := os.Open(file)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return hex.EncodeToString(h.Sum(nil)) == want, nil
}

// safeJoin recusa caminhos absolutos e com ".." (zip slip): tudo fica dentro de dest.
func safeJoin(dest, name string) (string, error) {
	slashed := strings.ReplaceAll(name, "\\", "/")
	clean := path.Clean("/" + slashed)
	if clean == "/" || strings.Contains(name, "\x00") {
		return "", fmt.Errorf("nome inválido no pacote: %q", name)
	}
	if strings.HasPrefix(slashed, "/") || strings.Contains("/"+slashed+"/", "/../") {
		return "", fmt.Errorf("caminho fora do destino no pacote: %q", name)
	}
	return filepath.Join(dest, filepath.FromSlash(clean[1:])), nil
}

// extract descompacta tar.gz ou zip só com diretórios e arquivos regulares; links e dispositivos são ignorados.
func extract(archive, dest string) (files, skipped int, err error) {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return 0, 0, err
	}
	var budget int64 = maxExtracted
	write := func(name string, mode os.FileMode, r io.Reader) error {
		target, err := safeJoin(dest, name)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, mode.Perm()&0o755|0o400)
		if err != nil {
			return err
		}
		n, err := io.Copy(f, io.LimitReader(r, budget+1))
		budget -= n
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if budget < 0 {
			return errors.New("conteúdo extraído passa do limite de 2 GiB")
		}
		files++
		return err
	}

	switch {
	case strings.HasSuffix(archive, ".zip"):
		zr, err := zip.OpenReader(archive)
		if err != nil {
			return 0, 0, err
		}
		defer func() { _ = zr.Close() }()
		for _, zf := range zr.File {
			if zf.FileInfo().IsDir() {
				continue
			}
			if !zf.Mode().IsRegular() {
				skipped++
				continue
			}
			rc, err := zf.Open()
			if err != nil {
				return files, skipped, err
			}
			err = write(zf.Name, zf.Mode(), rc)
			_ = rc.Close()
			if err != nil {
				return files, skipped, err
			}
		}
	case strings.HasSuffix(archive, ".tar.gz"), strings.HasSuffix(archive, ".tgz"):
		f, err := os.Open(archive)
		if err != nil {
			return 0, 0, err
		}
		defer func() { _ = f.Close() }()
		gz, err := gzip.NewReader(f)
		if err != nil {
			return 0, 0, err
		}
		tr := tar.NewReader(gz)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return files, skipped, err
			}
			switch hdr.Typeflag {
			case tar.TypeDir, tar.TypeXGlobalHeader:
				continue
			case tar.TypeReg:
				if err := write(hdr.Name, hdr.FileInfo().Mode(), tr); err != nil {
					return files, skipped, err
				}
			default:
				skipped++
			}
		}
	default:
		return 0, 0, fmt.Errorf("formato não suportado: %s", archive)
	}
	return files, skipped, nil
}
