package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

func (s *Service) tlsConfig(host string) *tls.Config {
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: s.RootCAs}
}

// heloName é o nome anunciado no EHLO: o nome do servidor, só com caracteres válidos.
func (s *Service) heloName() string {
	h := strings.Map(func(r rune) rune {
		if r == '.' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, s.Hostname)
	if h == "" {
		return "localhost"
	}
	return h
}

// sendEmail entrega a mensagem pelo SMTP configurado. STARTTLS é obrigatório no modo starttls (sem queda para texto
// puro); autenticação só acontece sobre TLS (ou no relé local, modo none).
func (s *Service) sendEmail(ctx context.Context, cfg EmailConfig, password string, m Message) error {
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return permanent{invalid("remetente inválido")}
	}
	var rcpts []*mail.Address
	for _, a := range cfg.To {
		addr, err := mail.ParseAddress(a)
		if err != nil {
			return permanent{invalid("destinatário inválido")}
		}
		rcpts = append(rcpts, addr)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(s.Timeout)
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	// SMTP costuma ser relé interno: rede privada é aceita, link-local e metadados não.
	dialer := &net.Dialer{Timeout: time.Until(deadline), Control: guardControl(true)}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if Permanent(err) {
			return err
		}
		return fmt.Errorf("SMTP: conexão com %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(deadline)
	// Cancelamento fecha a conexão e destrava qualquer leitura pendente.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if cfg.Security == SecurityTLS {
		tc := tls.Client(conn, s.tlsConfig(cfg.Host))
		if err := tc.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("SMTP: TLS com %s: %w", addr, err)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return smtpError("saudação", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello(s.heloName()); err != nil {
		return smtpError("EHLO", err)
	}
	if cfg.Security == SecuritySTARTTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return permanent{errors.New("SMTP: o servidor não oferece STARTTLS; use TLS (porta 465) ou outro servidor")}
		}
		if err := c.StartTLS(s.tlsConfig(cfg.Host)); err != nil {
			return smtpError("STARTTLS", err)
		}
	}
	if cfg.Username != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return permanent{errors.New("SMTP: o servidor não aceita autenticação (AUTH)")}
		}
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, password, cfg.Host)); err != nil {
			return smtpError("autenticação", err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return smtpError("MAIL FROM", err)
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r.Address); err != nil {
			return smtpError("RCPT TO "+r.Address, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return smtpError("DATA", err)
	}
	if _, err := w.Write(s.buildEmail(from, rcpts, m)); err != nil {
		return smtpError("DATA", err)
	}
	if err := w.Close(); err != nil {
		return smtpError("fim do DATA", err)
	}
	_ = c.Quit()
	return nil
}

// smtpError mantém o código do servidor: 5xx é recusa definitiva, 4xx é temporária.
func smtpError(stage string, err error) error {
	var te *textproto.Error
	if errors.As(err, &te) {
		e := fmt.Errorf("SMTP %s: %d %s", stage, te.Code, CleanText(te.Msg, 200))
		if te.Code >= 500 {
			return permanent{e}
		}
		return e
	}
	return fmt.Errorf("SMTP %s: %w", stage, err)
}

// buildEmail monta a mensagem RFC 5322 em texto puro UTF-8 (quoted-printable), com quebras CRLF.
func (s *Service) buildEmail(from *mail.Address, to []*mail.Address, m Message) []byte {
	var b bytes.Buffer
	header := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	header("From", from.String())
	tos := make([]string, len(to))
	for i, a := range to {
		tos[i] = a.String()
	}
	header("To", strings.Join(tos, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", m.Subject()))
	header("Date", s.now().Format(time.RFC1123Z))
	domain := "vigiahost.invalid"
	if at := strings.LastIndex(from.Address, "@"); at >= 0 {
		domain = from.Address[at+1:]
	}
	header("Message-ID", "<"+m.ID+"."+randomHex(6)+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "quoted-printable")
	header("Auto-Submitted", "auto-generated")
	header("X-VigiaHost-Event", m.Event)
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(strings.ReplaceAll(m.Text(), "\n", "\r\n")))
	_ = qp.Close()
	return b.Bytes()
}
