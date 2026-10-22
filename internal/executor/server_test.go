package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/ipc"
)

var testHello = ipc.Hello{ProtocolMajor: 1, ProtocolMinor: 0, Version: "teste"}

// startConn atende uma ponta de net.Pipe com a credencial informada e devolve a outra ponta.
func startConn(t *testing.T, cred Cred, handlers map[ipc.Op]Handler) net.Conn {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	s := &Server{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Policy:   Policy{AllowedUIDs: map[uint32]bool{990: true}},
		Local:    testHello,
		Handlers: handlers,
		PeerCred: func(net.Conn) (Cred, error) { return cred, nil },
	}
	done := make(chan struct{})
	go func() { s.ServeConn(context.Background(), serverSide); close(done) }()
	t.Cleanup(func() {
		clientSide.Close()
		<-done
	})
	return clientSide
}

// testCtx limita cada teste para que um impasse no protocolo falhe em vez de travar a suíte.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func handshaken(t *testing.T, conn net.Conn) (*ipc.Client, context.Context) {
	t.Helper()
	c := ipc.NewClient(conn)
	ctx := testCtx(t)
	if err := c.Handshake(ctx, testHello); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return c, ctx
}

func TestHandshakeECapacidades(t *testing.T) {
	handlers := map[ipc.Op]Handler{
		ipc.OpCapabilities: func(context.Context, json.RawMessage) (any, error) {
			return map[string]bool{"systemd": true}, nil
		},
	}
	c, ctx := handshaken(t, startConn(t, Cred{UID: 990}, handlers))
	if c.Remote.Version != "teste" {
		t.Errorf("versão remota = %q", c.Remote.Version)
	}
	var out map[string]bool
	if err := c.Call(ctx, ipc.OpCapabilities, nil, &out); err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	if !out["systemd"] {
		t.Errorf("resposta inesperada: %v", out)
	}
}

func TestRecusaUIDNaoAutorizado(t *testing.T) {
	conn := startConn(t, Cred{UID: 1000}, nil)
	// O executor responde e encerra sem ler nada do cliente não autorizado.
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var resp ipc.Response
	if err := ipc.NewClientCodec(conn).Read(&resp); err != nil {
		t.Fatalf("esperava resposta de recusa: %v", err)
	}
	if resp.OK || resp.Error == nil || resp.Error.Code != ipc.CodeUnauthorized {
		t.Fatalf("resposta inesperada: %+v", resp)
	}
}

func TestRootSempreAutorizado(t *testing.T) {
	handshaken(t, startConn(t, Cred{UID: 0}, nil))
}

func TestExigeHandshakeAntes(t *testing.T) {
	conn := startConn(t, Cred{UID: 990}, DefaultHandlers(nil, ""))
	err := ipc.NewClient(conn).Call(testCtx(t), ipc.OpCapabilities, nil, nil)
	assertCode(t, err, ipc.CodeHandshakeRequired)
}

func TestRecusaProtocoloIncompativel(t *testing.T) {
	conn := startConn(t, Cred{UID: 990}, nil)
	err := ipc.NewClient(conn).Handshake(testCtx(t), ipc.Hello{ProtocolMajor: 2, Version: "futura"})
	assertCode(t, err, ipc.CodeIncompatibleProtocol)
}

func TestOperacaoDesconhecidaNaoEncerraConexao(t *testing.T) {
	c, ctx := handshaken(t, startConn(t, Cred{UID: 990}, nil))
	assertCode(t, c.Call(ctx, ipc.Op("rm_rf"), nil, nil), ipc.CodeUnsupportedOp)
	// A conexão continua utilizável depois da recusa.
	if err := c.Call(ctx, ipc.OpHello, testHello, nil); err != nil {
		t.Fatalf("conexão deveria seguir aberta: %v", err)
	}
}

func TestErroInternoNaoVazaDetalhes(t *testing.T) {
	handlers := map[ipc.Op]Handler{
		ipc.OpCapabilities: func(context.Context, json.RawMessage) (any, error) {
			return nil, errors.New("detalhe sensível de /etc/shadow")
		},
	}
	c, ctx := handshaken(t, startConn(t, Cred{UID: 990}, handlers))
	err := c.Call(ctx, ipc.OpCapabilities, nil, nil)
	assertCode(t, err, ipc.CodeInternal)
	if strings.Contains(err.Error(), "shadow") {
		t.Errorf("mensagem vazou detalhe interno: %v", err)
	}
}

func TestMensagemGrandeEncerraConexao(t *testing.T) {
	conn := startConn(t, Cred{UID: 990}, nil)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	go conn.Write([]byte(strings.Repeat("a", ipc.MaxRequestSize+10) + "\n"))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("esperava conexão encerrada após mensagem acima do limite")
	}
}

func TestPolicy(t *testing.T) {
	p := Policy{AllowedUIDs: map[uint32]bool{990: true}}
	if p.Authorize(Cred{UID: 990}) != nil || p.Authorize(Cred{UID: 0}) != nil {
		t.Error("UIDs permitidos recusados")
	}
	if p.Authorize(Cred{UID: 33}) == nil {
		t.Error("UID não listado aceito")
	}
}

func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	ipcErr, ok := errors.AsType[*ipc.Error](err)
	if !ok {
		t.Fatalf("esperava erro %s, veio %v", code, err)
	}
	if ipcErr.Code != code {
		t.Fatalf("código = %s, esperado %s", ipcErr.Code, code)
	}
}
