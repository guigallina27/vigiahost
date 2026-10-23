// Package ipc define o protocolo entre o vigiahost-core e o vigiahost-executor: mensagens JSON,
// uma por linha, em um socket Unix, com tamanho limitado e operações tipadas. A autorização
// fica no executor (pacote executor); este pacote só trata formato e compatibilidade.
package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Limites por sentido. MaxRequestSize protege a memória do executor contra um cliente comprometido e cabe um
// run.start com milhares de contas (um caminho e um UID por conta). MaxResponseSize vale para o que o core lê do
// executor, que é root e confiável, e cabe a lista de contas de um servidor grande (dezenas de milhares).
const (
	MaxRequestSize  = 2 << 20
	MaxResponseSize = 16 << 20
)

// Op identifica uma operação tipada aceita pelo executor.
type Op string

const (
	OpHello        Op = "hello"
	OpCapabilities Op = "capabilities"
)

// Códigos de erro estáveis, usados pelo core para decidir o que mostrar ao operador.
const (
	CodeBadRequest           = "bad_request"
	CodeUnauthorized         = "unauthorized"
	CodeUnsupportedOp        = "unsupported_op"
	CodeIncompatibleProtocol = "incompatible_protocol"
	CodeHandshakeRequired    = "handshake_required"
	CodeInternal             = "internal"
)

// ErrMessageTooLarge indica mensagem acima do limite do sentido; a conexão deve ser encerrada.
var ErrMessageTooLarge = errors.New("mensagem acima do limite do protocolo")

type Request struct {
	ID   uint64          `json:"id"`
	Op   Op              `json:"op"`
	Body json.RawMessage `json:"body,omitempty"`
}

type Response struct {
	ID    uint64          `json:"id"`
	OK    bool            `json:"ok"`
	Error *Error          `json:"error,omitempty"`
	Body  json.RawMessage `json:"body,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Hello é trocado na abertura de cada conexão, nos dois sentidos.
type Hello struct {
	ProtocolMajor int    `json:"protocol_major"`
	ProtocolMinor int    `json:"protocol_minor"`
	Version       string `json:"version"`
}

func (h Hello) Protocol() string { return fmt.Sprintf("%d.%d", h.ProtocolMajor, h.ProtocolMinor) }

// Compatible exige a mesma versão principal do protocolo; versões secundárias diferentes convivem.
func Compatible(local, remote Hello) error {
	if local.ProtocolMajor != remote.ProtocolMajor {
		return &Error{
			Code:    CodeIncompatibleProtocol,
			Message: fmt.Sprintf("protocolo %s incompatível com %s", remote.Protocol(), local.Protocol()),
		}
	}
	return nil
}

// Codec lê e escreve mensagens delimitadas por nova linha.
type Codec struct {
	r        *bufio.Reader
	w        io.Writer
	readMax  int
	writeMax int
}

// NewCodec usa MaxRequestSize nos dois sentidos.
func NewCodec(rw io.ReadWriter) *Codec { return newCodec(rw, MaxRequestSize, MaxRequestSize) }

// NewServerCodec é o lado do executor: lê pedidos e escreve respostas.
func NewServerCodec(rw io.ReadWriter) *Codec { return newCodec(rw, MaxRequestSize, MaxResponseSize) }

// NewClientCodec é o lado do core: escreve pedidos e lê respostas.
func NewClientCodec(rw io.ReadWriter) *Codec { return newCodec(rw, MaxResponseSize, MaxRequestSize) }

func newCodec(rw io.ReadWriter, readMax, writeMax int) *Codec {
	return &Codec{r: bufio.NewReaderSize(rw, 64<<10), w: rw, readMax: readMax, writeMax: writeMax}
}

// Read decodifica a próxima mensagem em v. Depois de ErrMessageTooLarge o fluxo fica dessincronizado.
func (c *Codec) Read(v any) error {
	line, err := c.readLine()
	if err != nil {
		return err
	}
	if err := json.Unmarshal(line, v); err != nil {
		return fmt.Errorf("mensagem inválida: %w", err)
	}
	return nil
}

// Write codifica v em uma linha.
func (c *Codec) Write(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > c.writeMax {
		return ErrMessageTooLarge
	}
	_, err = c.w.Write(append(data, '\n'))
	return err
}

func (c *Codec) readLine() ([]byte, error) {
	var line []byte
	for {
		chunk, err := c.r.ReadSlice('\n')
		if len(line)+len(chunk) > c.readMax+1 {
			return nil, ErrMessageTooLarge
		}
		line = append(line, chunk...)
		switch {
		case err == nil:
			return line[:len(line)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(line) > 0:
			return nil, io.ErrUnexpectedEOF
		default:
			return nil, err
		}
	}
}
