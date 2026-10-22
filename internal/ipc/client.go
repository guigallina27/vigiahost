package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// Client mantém uma conexão com o executor. Não é seguro para uso concorrente.
type Client struct {
	conn   net.Conn
	codec  *Codec
	nextID uint64
	// Remote é o Hello devolvido pelo executor no handshake.
	Remote Hello
}

// Dial conecta ao socket do executor e faz o handshake de versão.
func Dial(ctx context.Context, socketPath string, local Hello) (*Client, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, err
	}
	c := NewClient(conn)
	if err := c.Handshake(ctx, local); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// NewClient usa uma conexão já aberta; o handshake ainda precisa ser feito.
func NewClient(conn net.Conn) *Client {
	return &Client{conn: conn, codec: NewClientCodec(conn)}
}

func (c *Client) Handshake(ctx context.Context, local Hello) error {
	var remote Hello
	if err := c.Call(ctx, OpHello, local, &remote); err != nil {
		return err
	}
	if err := Compatible(local, remote); err != nil {
		return err
	}
	c.Remote = remote
	return nil
}

// Call envia uma operação e espera a resposta correspondente. Erros do executor voltam como *Error.
func (c *Client) Call(ctx context.Context, op Op, in, out any) error {
	if dl, ok := ctx.Deadline(); ok {
		c.conn.SetDeadline(dl)
	} else {
		c.conn.SetDeadline(time.Time{})
	}
	stop := context.AfterFunc(ctx, func() { c.conn.SetDeadline(time.Now()) })
	defer stop()

	c.nextID++
	req := Request{ID: c.nextID, Op: op}
	if in != nil {
		body, err := json.Marshal(in)
		if err != nil {
			return err
		}
		req.Body = body
	}
	if err := c.codec.Write(req); err != nil {
		return c.wrap(ctx, err)
	}
	var resp Response
	if err := c.codec.Read(&resp); err != nil {
		return c.wrap(ctx, err)
	}
	if !resp.OK {
		if resp.Error != nil {
			return resp.Error
		}
		return errors.New("executor recusou a operação sem detalhar o motivo")
	}
	if resp.ID != req.ID {
		return fmt.Errorf("resposta %d não corresponde à requisição %d", resp.ID, req.ID)
	}
	if out != nil {
		if err := json.Unmarshal(resp.Body, out); err != nil {
			return fmt.Errorf("resposta inválida para %s: %w", op, err)
		}
	}
	return nil
}

func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) wrap(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}
