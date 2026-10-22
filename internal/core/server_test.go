package core

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/guigallina27/vigiahost/internal/api"
	"github.com/guigallina27/vigiahost/internal/sysinfo"
	"github.com/guigallina27/vigiahost/internal/webui"
)

func newTestServer(st ExecutorStatus) http.Handler {
	s := &Server{
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version: "0.0.1",
		Probe:   func(context.Context) ExecutorStatus { return st },
	}
	return s.Handler()
}

func TestHealthComExecutorConectado(t *testing.T) {
	h := newTestServer(ExecutorStatus{Connected: true, Version: "0.0.1", Protocol: "1.0",
		System: &sysinfo.Capabilities{DistroID: "almalinux", DistroLike: []string{"rhel"}, CgroupV2: true}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body api.Health
	dec := json.NewDecoder(rec.Body)
	dec.DisallowUnknownFields() // o contrato tem additionalProperties: false
	if err := dec.Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != api.HealthStatusOk || body.Version != "0.0.1" || !body.Executor.Connected {
		t.Errorf("corpo inesperado: %+v", body)
	}
	if sys := body.Executor.System; sys == nil || sys.DistroId != "almalinux" || !sys.CgroupV2 || sys.DistroLike == nil || (*sys.DistroLike)[0] != "rhel" {
		t.Errorf("capacidades do sistema não repassadas: %+v", sys)
	}
	if body.Executor.Error != nil {
		t.Errorf("campo error deveria ser omitido: %q", *body.Executor.Error)
	}
	for _, header := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"} {
		if rec.Header().Get(header) == "" {
			t.Errorf("cabeçalho %s ausente", header)
		}
	}
}

func TestHealthDegradadoSemExecutor(t *testing.T) {
	h := newTestServer(ExecutorStatus{Error: "connection refused"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, esperado 503", rec.Code)
	}
}

func TestMetodoNaoPermitido(t *testing.T) {
	h := newTestServer(ExecutorStatus{Connected: true})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/health", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, esperado 405", rec.Code)
	}
}

func TestRecusaRequisicaoDeOutraOrigem(t *testing.T) {
	h := newTestServer(ExecutorStatus{Connected: true})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/health", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, esperado 403", rec.Code)
	}
}

func TestRotaInexistenteDaAPIRespondeJSON(t *testing.T) {
	s := &Server{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Probe: func(context.Context) ExecutorStatus { return ExecutorStatus{} },
		UI: webui.New(fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}})}
	h := s.Handler()
	for _, target := range []string{"/api/v1/nada", "/api"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusNotFound || rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
			t.Errorf("%s: status %d, Content-Type %q", target, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/execucoes", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "<!doctype html>" {
		t.Errorf("rota da interface: status %d, corpo %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("interface sem CSP")
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/health", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE com interface ativa: status %d, esperado 405", rec.Code)
	}
}
