package ipc

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type rw struct {
	io.Reader
	io.Writer
}

func TestCodecIdaEVolta(t *testing.T) {
	var buf bytes.Buffer
	c := NewCodec(&buf)
	in := Request{ID: 7, Op: OpHello, Body: []byte(`{"version":"1"}`)}
	if err := c.Write(in); err != nil {
		t.Fatal(err)
	}
	var out Request
	if err := c.Read(&out); err != nil {
		t.Fatal(err)
	}
	if out.ID != 7 || out.Op != OpHello || string(out.Body) != `{"version":"1"}` {
		t.Errorf("mensagem alterada: %+v", out)
	}
}

func TestCodecLimiteDeTamanho(t *testing.T) {
	line := strings.Repeat("x", MaxRequestSize+1) + "\n"
	c := NewCodec(rw{strings.NewReader(line), io.Discard})
	var v any
	if err := c.Read(&v); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("esperava ErrMessageTooLarge, veio %v", err)
	}
}

func TestCodecMensagemNoLimiteExato(t *testing.T) {
	payload := `"` + strings.Repeat("y", MaxRequestSize-2) + `"`
	c := NewCodec(rw{strings.NewReader(payload + "\n"), io.Discard})
	var v string
	if err := c.Read(&v); err != nil {
		t.Fatalf("mensagem de %d bytes deveria passar: %v", len(payload), err)
	}
}

func TestCodecLinhaTruncada(t *testing.T) {
	c := NewCodec(rw{strings.NewReader(`{"id":1`), io.Discard})
	var v Request
	if err := c.Read(&v); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("esperava ErrUnexpectedEOF, veio %v", err)
	}
}

func TestCodecJSONInvalido(t *testing.T) {
	c := NewCodec(rw{strings.NewReader("não é json\n"), io.Discard})
	var v Request
	if err := c.Read(&v); err == nil {
		t.Fatal("esperava erro de JSON")
	}
}

func TestCompatible(t *testing.T) {
	a := Hello{ProtocolMajor: 1, ProtocolMinor: 0}
	if err := Compatible(a, Hello{ProtocolMajor: 1, ProtocolMinor: 3}); err != nil {
		t.Errorf("versões secundárias diferentes deveriam conviver: %v", err)
	}
	err := Compatible(a, Hello{ProtocolMajor: 2})
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeIncompatibleProtocol {
		t.Errorf("esperava incompatible_protocol, veio %v", err)
	}
}

func FuzzCodecRead(f *testing.F) {
	f.Add([]byte(`{"id":1,"op":"hello","body":{"protocol_major":1}}` + "\n"))
	f.Add([]byte("\n\n"))
	f.Add([]byte(`{"id":-1}` + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c := NewCodec(rw{bytes.NewReader(data), io.Discard})
		for range 4 {
			var req Request
			if err := c.Read(&req); err != nil {
				return
			}
		}
	})
}

func TestCodecLimitesPorSentido(t *testing.T) {
	// Resposta grande (ex.: lista de contas) passa no lado do core e é recusada se chegasse como pedido ao executor.
	payload := `"` + strings.Repeat("z", MaxRequestSize+10) + `"` + "\n"
	var v string
	if err := NewClientCodec(rw{strings.NewReader(payload), io.Discard}).Read(&v); err != nil {
		t.Fatalf("o core deveria aceitar resposta de %d bytes: %v", len(payload), err)
	}
	if err := NewServerCodec(rw{strings.NewReader(payload), io.Discard}).Read(&v); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("o executor deveria recusar pedido de %d bytes, veio %v", len(payload), err)
	}
	big := strings.Repeat("w", MaxRequestSize+10)
	if err := NewServerCodec(rw{strings.NewReader(""), io.Discard}).Write(big); err != nil {
		t.Fatalf("o executor deveria conseguir responder %d bytes: %v", len(big), err)
	}
	if err := NewClientCodec(rw{strings.NewReader(""), io.Discard}).Write(big); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("o core não deveria enviar pedido de %d bytes, veio %v", len(big), err)
	}
}
