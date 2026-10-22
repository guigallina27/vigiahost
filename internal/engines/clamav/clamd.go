// Package clamav é o adaptador do ClamAV (ADR-006): cliente nativo do protocolo do clamd por socket Unix, com o
// arquivo entregue pelo descritor (FILDES) e conteúdo em memória por INSTREAM, e o clamscan para arquivos acima
// dos limites do clamd. As respostas do clamd citam só "fd[N]" ou "stream", nunca o nome do arquivo.
package clamav

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// Verdict é a resposta do clamd para um arquivo.
type Verdict struct {
	Found     bool
	Signature string
	// Err é preenchido quando o clamd respondeu ERROR (ex.: limite atingido) ou a conversa falhou.
	Err error
}

// Client conversa com o clamd. É seguro para uso concorrente: cada chamada abre a própria conexão.
type Client struct {
	Socket  string
	Timeout time.Duration // por arquivo; 0 = 2 minutos
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 2 * time.Minute
}

func (c *Client) dial(ctx context.Context) (*net.UnixConn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, err
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("clamd: socket não é Unix")
	}
	deadline := time.Now().Add(c.timeout())
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = uc.SetDeadline(deadline)
	return uc, nil
}

// command envia um comando simples (zVERSION, zPING...) e devolve a resposta sem o NUL final.
func (c *Client) command(ctx context.Context, cmd string) (string, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("z" + cmd + "\x00")); err != nil {
		return "", err
	}
	return readReply(conn)
}

// Ping confere se o clamd responde.
func (c *Client) Ping(ctx context.Context) error {
	r, err := c.command(ctx, "PING")
	if err != nil {
		return err
	}
	if r != "PONG" {
		return fmt.Errorf("clamd: resposta inesperada ao PING: %q", r)
	}
	return nil
}

// VersionInfo separa a versão do motor e a do banco de assinaturas.
type VersionInfo struct {
	Engine    string // 1.4.6
	Database  string // 27800
	BuiltAt   string // data do banco
	Signature string // texto completo
}

// Version consulta "ClamAV 1.4.6/27800/Wed Oct 22 08:00:00 2026".
func (c *Client) Version(ctx context.Context) (VersionInfo, error) {
	r, err := c.command(ctx, "VERSION")
	if err != nil {
		return VersionInfo{}, err
	}
	return ParseVersion(r), nil
}

// ParseVersion interpreta a linha de versão do clamd ou do clamscan --version.
func ParseVersion(s string) VersionInfo {
	v := VersionInfo{Signature: strings.TrimSpace(s)}
	parts := strings.SplitN(strings.TrimPrefix(v.Signature, "ClamAV "), "/", 3)
	v.Engine = strings.TrimSpace(parts[0])
	if len(parts) > 1 {
		v.Database = parts[1]
	}
	if len(parts) > 2 {
		v.BuiltAt = parts[2]
	}
	return v
}

// ScanFD entrega o descritor ao clamd (FILDES). O clamd precisa estar na mesma máquina (socket Unix).
func (c *Client) ScanFD(ctx context.Context, f *os.File) Verdict {
	conn, err := c.dial(ctx)
	if err != nil {
		return Verdict{Err: err}
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("zFILDES\x00")); err != nil {
		return Verdict{Err: err}
	}
	// Um byte de dados acompanha a mensagem de controle com o descritor, como no clamdscan.
	rights := unixRights(int(f.Fd()))
	if _, _, err := conn.WriteMsgUnix([]byte{0}, rights, nil); err != nil {
		return Verdict{Err: fmt.Errorf("envio do descritor: %w", err)}
	}
	reply, err := readReply(conn)
	if err != nil {
		return Verdict{Err: err}
	}
	return ParseReply(reply)
}

// maxChunk é o tamanho de cada bloco do INSTREAM (o clamd aceita até StreamMaxLength no total).
const maxChunk = 64 << 10

// ScanStream envia o conteúdo por INSTREAM (usado no autoteste e para conteúdo já em memória).
func (c *Client) ScanStream(ctx context.Context, r io.Reader) Verdict {
	conn, err := c.dial(ctx)
	if err != nil {
		return Verdict{Err: err}
	}
	defer func() { _ = conn.Close() }()
	w := bufio.NewWriter(conn)
	if _, err := w.WriteString("zINSTREAM\x00"); err != nil {
		return Verdict{Err: err}
	}
	buf := make([]byte, maxChunk)
	var size [4]byte
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(size[:], uint32(n)) //nolint:gosec // n <= maxChunk
			if _, err := w.Write(size[:]); err != nil {
				return Verdict{Err: err}
			}
			if _, err := w.Write(buf[:n]); err != nil {
				return Verdict{Err: err}
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return Verdict{Err: rerr}
		}
	}
	binary.BigEndian.PutUint32(size[:], 0)
	if _, err := w.Write(size[:]); err != nil {
		return Verdict{Err: err}
	}
	if err := w.Flush(); err != nil {
		return Verdict{Err: err}
	}
	reply, err := readReply(conn)
	if err != nil {
		return Verdict{Err: err}
	}
	return ParseReply(reply)
}

// ParseReply interpreta "fd[10]: OK", "stream: Eicar-Test-Signature FOUND" ou "... ERROR".
func ParseReply(reply string) Verdict {
	_, rest, ok := strings.Cut(reply, ": ")
	if !ok {
		return Verdict{Err: fmt.Errorf("resposta do clamd não reconhecida: %q", reply)}
	}
	switch {
	case rest == "OK":
		return Verdict{}
	case strings.HasSuffix(rest, " FOUND"):
		return Verdict{Found: true, Signature: strings.TrimSuffix(rest, " FOUND")}
	case strings.HasSuffix(rest, " ERROR"):
		return Verdict{Err: errors.New(strings.TrimSuffix(rest, " ERROR"))}
	}
	return Verdict{Err: fmt.Errorf("resposta do clamd não reconhecida: %q", reply)}
}

// maxReply limita a resposta lida (o clamd responde em poucas dezenas de bytes).
const maxReply = 4096

func readReply(r io.Reader) (string, error) {
	br := bufio.NewReaderSize(io.LimitReader(r, maxReply), 512)
	line, err := br.ReadBytes(0)
	if err != nil && (!errors.Is(err, io.EOF) || len(line) == 0) {
		if errors.Is(err, io.EOF) {
			return "", errors.New("clamd encerrou a conexão sem responder")
		}
		return "", err
	}
	return string(bytes.TrimRight(line, "\x00\n")), nil
}
