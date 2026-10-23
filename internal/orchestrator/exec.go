// Package orchestrator coordena as execuções no core: fila no SQLite, despacho ao executor, acompanhamento,
// ingestão dos achados, agendamentos e recuperação depois de reinício (ADR-003 e ADR-014).
package orchestrator

import (
	"context"
	"errors"
	"sync"

	"github.com/guigallina27/vigiahost/internal/ipc"
)

// Executor é o que o orquestrador precisa do executor; os testes trocam por um falso.
type Executor interface {
	Call(ctx context.Context, op ipc.Op, in, out any) error
}

// ExecClient mantém uma conexão com o executor, serializa as chamadas e reconecta quando ela cai.
type ExecClient struct {
	Socket string
	Local  ipc.Hello

	mu sync.Mutex
	c  *ipc.Client
}

// Call faz a chamada; se a conexão estiver quebrada, reconecta e tenta mais uma vez. Erros do executor (*ipc.Error)
// voltam direto, sem nova tentativa.
func (e *ExecClient) Call(ctx context.Context, op ipc.Op, in, out any) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for attempt := 0; ; attempt++ {
		if e.c == nil {
			c, err := ipc.Dial(ctx, e.Socket, e.Local)
			if err != nil {
				return &Unavailable{Err: err}
			}
			e.c = c
		}
		err := e.c.Call(ctx, op, in, out)
		var ie *ipc.Error
		if err == nil || errors.As(err, &ie) || ctx.Err() != nil {
			return err
		}
		_ = e.c.Close()
		e.c = nil
		// Conexão velha (executor reiniciado) falha na primeira chamada: reconecta e tenta de novo uma vez.
		if attempt > 0 {
			return &Unavailable{Err: err}
		}
	}
}

// Close encerra a conexão.
func (e *ExecClient) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.c != nil {
		_ = e.c.Close()
		e.c = nil
	}
}

// Unavailable indica executor fora do ar: a execução volta para a fila em vez de falhar.
type Unavailable struct{ Err error }

func (u *Unavailable) Error() string { return "executor indisponível: " + u.Err.Error() }
func (u *Unavailable) Unwrap() error { return u.Err }

// IsUnavailable diz se o erro é de conexão com o executor.
func IsUnavailable(err error) bool {
	var u *Unavailable
	return errors.As(err, &u)
}
