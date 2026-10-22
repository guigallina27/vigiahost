package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":              {Data: []byte("<!doctype html><title>VigiaHost</title>")},
		"theme-init.js":           {Data: []byte("/* tema */")},
		"assets/app-abc123.js":    {Data: []byte("console.log(1)")},
		"assets/app-abc123.js.br": {Data: []byte("brotli")},
		"assets/app-abc123.js.gz": {Data: []byte("gzip")},
		"assets/font-1a2b.woff2":  {Data: []byte("woff2")},
	}
}

func get(t *testing.T, h http.Handler, target, acceptEncoding string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRotaDaInterfaceRecebeIndex(t *testing.T) {
	h := New(testFS())
	for _, target := range []string{"/", "/execucoes", "/configuracoes/aparencia", "/../../etc/passwd"} {
		rec := get(t, h, target, "")
		if rec.Code != http.StatusOK || rec.Body.String() != "<!doctype html><title>VigiaHost</title>" {
			t.Errorf("%s: status %d, corpo %q", target, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
			t.Errorf("%s: Cache-Control = %q", target, got)
		}
	}
}

func TestAssetsComHashFicamEmCacheEUsamCompressao(t *testing.T) {
	h := New(testFS())
	cases := []struct{ accept, encoding, body string }{
		{"gzip, deflate, br, zstd", "br", "brotli"},
		{"gzip", "gzip", "gzip"},
		{"br;q=0, gzip", "gzip", "gzip"},
		{"", "", "console.log(1)"},
	}
	for _, c := range cases {
		rec := get(t, h, "/assets/app-abc123.js", c.accept)
		if rec.Code != http.StatusOK || rec.Body.String() != c.body {
			t.Errorf("Accept-Encoding %q: status %d, corpo %q", c.accept, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Encoding"); got != c.encoding {
			t.Errorf("Accept-Encoding %q: Content-Encoding = %q, esperado %q", c.accept, got, c.encoding)
		}
		if got := rec.Header().Get("Content-Type"); got != "text/javascript; charset=utf-8" {
			t.Errorf("Content-Type = %q", got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
			t.Errorf("Cache-Control = %q", got)
		}
	}
	if got := get(t, h, "/assets/font-1a2b.woff2", "").Header().Get("Content-Type"); got != "font/woff2" {
		t.Errorf("fonte com Content-Type %q", got)
	}
}

func TestArquivoInexistenteNaoCaiNoIndex(t *testing.T) {
	h := New(testFS())
	for _, target := range []string{"/assets/sumiu-123.js", "/assets/sem-extensao", "/favicon.ico", "/x.php"} {
		if rec := get(t, h, target, ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, esperado 404", target, rec.Code)
		}
	}
}

func TestSemInterfaceConstruida(t *testing.T) {
	rec := get(t, New(fstest.MapFS{"README.txt": {Data: []byte("x")}}), "/", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, esperado 404", rec.Code)
	}
}

func TestMetodoNaoPermitido(t *testing.T) {
	rec := httptest.NewRecorder()
	New(testFS()).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, esperado 405", rec.Code)
	}
}

func TestHandlerEmbarcadoCompila(t *testing.T) {
	// Com ou sem o build da interface, o handler embarcado precisa responder sem pânico.
	rec := get(t, Handler(), "/", "")
	if rec.Code != http.StatusOK && rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
}
