package core

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
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
	h := newTestServer(ExecutorStatus{Connected: true, Version: "0.0.1", Protocol: "1.0"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body healthResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ok" || body.Version != "0.0.1" || !body.Executor.Connected {
		t.Errorf("corpo inesperado: %+v", body)
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
