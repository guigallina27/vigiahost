// Package webui serve a interface React embarcada no binário (ADR-001).
// O build da interface (make web) grava em dist/; sem ele, o binário funciona só com a API.
package webui

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var embedded embed.FS

// contentTypes cobre só o que o build gera; não depende do /etc/mime.types do servidor.
var contentTypes = map[string]string{
	".html":  "text/html; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".svg":   "image/svg+xml",
	".woff2": "font/woff2",
	".json":  "application/json",
	".txt":   "text/plain; charset=utf-8",
}

// Handler devolve o servidor de arquivos da interface a partir do conteúdo embarcado.
func Handler() http.Handler {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		panic(err) // dist/ é embarcado em tempo de compilação; só falha se o padrão do embed mudar.
	}
	return New(sub)
}

// New serve os arquivos de root:
//   - /assets/* têm hash no nome e ficam em cache por um ano;
//   - os demais arquivos e o index.html são revalidados a cada acesso;
//   - caminhos sem extensão são rotas da interface e recebem o index.html;
//   - versões .br e .gz geradas no build são entregues a quem aceita a compressão.
func New(root fs.FS) http.Handler {
	_, err := fs.Stat(root, "index.html")
	built := err == nil
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "método não permitido", http.StatusMethodNotAllowed)
			return
		}
		if !built {
			http.Error(w, "interface não incluída neste binário; gere com make web antes do build", http.StatusNotFound)
			return
		}

		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		immutable := strings.HasPrefix(name, "assets/")
		if name == "" || (path.Ext(name) == "" && !immutable) {
			name = "index.html"
		}
		if !serveFile(w, r, root, name, immutable) {
			http.NotFound(w, r)
		}
	})
}

func serveFile(w http.ResponseWriter, r *http.Request, root fs.FS, name string, immutable bool) bool {
	ctype, ok := contentTypes[path.Ext(name)]
	if !ok {
		return false
	}
	h := w.Header()
	if immutable {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "no-cache")
	}
	h.Set("Content-Type", ctype)
	h.Add("Vary", "Accept-Encoding")

	accept := r.Header.Get("Accept-Encoding")
	for _, enc := range []struct{ token, ext string }{{"br", ".br"}, {"gzip", ".gz"}} {
		if acceptsEncoding(accept, enc.token) && open(w, r, root, name+enc.ext, enc.token) {
			return true
		}
	}
	return open(w, r, root, name, "")
}

func open(w http.ResponseWriter, r *http.Request, root fs.FS, name, encoding string) bool {
	f, err := root.Open(name)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return false
	}
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		return false
	}
	if encoding != "" {
		w.Header().Set("Content-Encoding", encoding)
	}
	http.ServeContent(w, r, name, st.ModTime(), rs)
	return true
}

// acceptsEncoding confere o token no Accept-Encoding, respeitando q=0 como recusa.
func acceptsEncoding(header, token string) bool {
	for part := range strings.SplitSeq(header, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(name), token) {
			continue
		}
		q := strings.ReplaceAll(strings.TrimSpace(params), " ", "")
		return q != "q=0" && q != "q=0.0" && q != "q=0.00" && q != "q=0.000"
	}
	return false
}
