// Package executor implementa o lado privilegiado: aceita conexões no socket Unix, confere quem está
// do outro lado (SO_PEERCRED), aplica a política própria e despacha apenas operações tipadas.
// Parte do princípio de que o core pode estar comprometido.
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/guigallina27/vigiahost/internal/ipc"
)

// Cred identifica o processo do outro lado do socket.
type Cred struct {
	PID int32
	UID uint32
	GID uint32
}

// Policy decide quem pode falar com o executor. Root é sempre aceito (CLI local de diagnóstico).
type Policy struct {
	AllowedUIDs map[uint32]bool
}

func (p Policy) Authorize(c Cred) error {
	if c.UID == 0 || p.AllowedUIDs[c.UID] {
		return nil
	}
	return fmt.Errorf("UID %d não autorizado", c.UID)
}

// Handler executa uma operação já autorizada. Erros do tipo *ipc.Error chegam ao cliente como estão;
// os demais viram erro interno, sem detalhes, e ficam só no log.
type Handler func(ctx context.Context, body json.RawMessage) (any, error)

type Server struct {
	Logger   *slog.Logger
	Policy   Policy
	Local    ipc.Hello
	Handlers map[ipc.Op]Handler
	// IdleTimeout encerra conexões paradas; WriteTimeout limita o envio de cada resposta.
	IdleTimeout  time.Duration
	WriteTimeout time.Duration
	MaxConns     int
	// PeerCred obtém a credencial do cliente; nil usa SO_PEERCRED.
	PeerCred func(net.Conn) (Cred, error)
}

// Serve atende até o contexto ser cancelado.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	maxConns := s.MaxConns
	if maxConns <= 0 {
		maxConns = 16
	}
	sem := make(chan struct{}, maxConns)
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()

	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			s.Logger.Warn("conexão recusada: limite de conexões simultâneas atingido", "limite", maxConns)
			conn.Close()
			continue
		}
		wg.Go(func() {
			defer func() { <-sem }()
			s.ServeConn(ctx, conn)
		})
	}
}

// ServeConn atende uma conexão: autoriza, exige o handshake como primeira mensagem e despacha as operações.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	peerCred := s.PeerCred
	if peerCred == nil {
		peerCred = PeerCredential
	}
	cred, err := peerCred(conn)
	if err != nil {
		s.Logger.Warn("conexão recusada: credencial do cliente indisponível", "erro", err)
		return
	}
	log := s.Logger.With("pid", cred.PID, "uid", cred.UID)
	codec := ipc.NewServerCodec(conn)

	if err := s.Policy.Authorize(cred); err != nil {
		log.Warn("conexão recusada pela política", "motivo", err.Error())
		conn.SetWriteDeadline(time.Now().Add(s.writeTimeout()))
		_ = codec.Write(ipc.Response{Error: &ipc.Error{Code: ipc.CodeUnauthorized, Message: "cliente não autorizado"}})
		return
	}

	handshaken := false
	for {
		conn.SetReadDeadline(time.Now().Add(s.idleTimeout()))
		var req ipc.Request
		if err := codec.Read(&req); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Warn("conexão encerrada por mensagem inválida ou inatividade", "erro", err)
			}
			return
		}
		resp, closeAfter := s.dispatch(ctx, &handshaken, req, log)
		conn.SetWriteDeadline(time.Now().Add(s.writeTimeout()))
		if err := codec.Write(resp); err != nil || closeAfter {
			return
		}
	}
}

func (s *Server) dispatch(ctx context.Context, handshaken *bool, req ipc.Request, log *slog.Logger) (ipc.Response, bool) {
	resp := ipc.Response{ID: req.ID}

	if req.Op == ipc.OpHello {
		var remote ipc.Hello
		if err := json.Unmarshal(req.Body, &remote); err != nil {
			resp.Error = &ipc.Error{Code: ipc.CodeBadRequest, Message: "hello inválido"}
			return resp, true
		}
		if err := ipc.Compatible(s.Local, remote); err != nil {
			log.Warn("handshake recusado", "versao_cliente", remote.Version, "protocolo_cliente", remote.Protocol())
			resp.Error, _ = errors.AsType[*ipc.Error](err)
			return resp, true
		}
		*handshaken = true
		resp.OK = true
		resp.Body, _ = json.Marshal(s.Local)
		log.Info("cliente conectado", "versao_cliente", remote.Version, "protocolo_cliente", remote.Protocol())
		return resp, false
	}

	if !*handshaken {
		resp.Error = &ipc.Error{Code: ipc.CodeHandshakeRequired, Message: "a primeira mensagem deve ser hello"}
		return resp, true
	}

	handler, ok := s.Handlers[req.Op]
	if !ok {
		log.Warn("operação desconhecida recusada", "op", string(req.Op))
		resp.Error = &ipc.Error{Code: ipc.CodeUnsupportedOp, Message: "operação não suportada"}
		return resp, false
	}

	out, err := handler(ctx, req.Body)
	if err != nil {
		if ipcErr, ok := errors.AsType[*ipc.Error](err); ok {
			resp.Error = ipcErr
		} else {
			log.Error("falha ao executar operação", "op", string(req.Op), "erro", err)
			resp.Error = &ipc.Error{Code: ipc.CodeInternal, Message: "falha interna no executor"}
		}
		return resp, false
	}
	body, err := json.Marshal(out)
	if err != nil {
		log.Error("falha ao codificar resposta", "op", string(req.Op), "erro", err)
		resp.Error = &ipc.Error{Code: ipc.CodeInternal, Message: "falha interna no executor"}
		return resp, false
	}
	resp.OK = true
	resp.Body = body
	log.Info("operação executada", "op", string(req.Op))
	return resp, false
}

func (s *Server) idleTimeout() time.Duration {
	if s.IdleTimeout > 0 {
		return s.IdleTimeout
	}
	return 5 * time.Minute
}

func (s *Server) writeTimeout() time.Duration {
	if s.WriteTimeout > 0 {
		return s.WriteTimeout
	}
	return 10 * time.Second
}
