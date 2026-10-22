package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/textproto"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/secrets"
	"github.com/guigallina27/vigiahost/internal/store"
)

// testCert gera um certificado autoassinado para 127.0.0.1 e localhost e o conjunto de raízes que confia nele.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake-smtp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

type fakeMail struct {
	From     string
	To       []string
	Data     string
	User     string
	Pass     string
	TLS      bool
	Greeting string
}

// fakeSMTP é um servidor SMTP mínimo para os testes: EHLO, STARTTLS, AUTH PLAIN, MAIL, RCPT, DATA e QUIT.
type fakeSMTP struct {
	t        *testing.T
	ln       net.Listener
	port     int
	cert     tls.Certificate
	starttls bool   // anuncia STARTTLS
	implicit bool   // TLS desde a conexão
	user     string // usuário e senha aceitos; vazio não anuncia AUTH
	pass     string
	rcptCode int // resposta ao RCPT (0 = 250)

	mu    sync.Mutex
	mails []fakeMail
}

func startSMTP(t *testing.T, cert tls.Certificate, configure func(*fakeSMTP)) *fakeSMTP {
	t.Helper()
	f := &fakeSMTP{t: t, cert: cert}
	configure(f)
	var err error
	f.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if f.implicit {
		f.ln = tls.NewListener(f.ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
	f.port = f.ln.Addr().(*net.TCPAddr).Port
	t.Cleanup(func() { _ = f.ln.Close() })
	go func() {
		for {
			c, err := f.ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) received() []fakeMail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeMail(nil), f.mails...)
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	isTLS := f.implicit
	tp := textproto.NewConn(c)
	m := fakeMail{TLS: isTLS}
	reply := func(s string) { _ = tp.PrintfLine("%s", s) }
	reply("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		cmd, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(cmd) {
		case "EHLO", "HELO":
			m.Greeting = arg
			lines := []string{"250-fake"}
			if f.starttls && !isTLS {
				lines = append(lines, "250-STARTTLS")
			}
			if f.user != "" {
				lines = append(lines, "250-AUTH PLAIN")
			}
			lines = append(lines, "250 8BITMIME")
			for _, l := range lines {
				reply(l)
			}
		case "STARTTLS":
			reply("220 pronto para TLS")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.cert}, MinVersion: tls.VersionTLS12})
			if err := tc.Handshake(); err != nil {
				return
			}
			c, isTLS, m.TLS = tc, true, true
			tp = textproto.NewConn(c)
		case "AUTH":
			parts := strings.Fields(arg)
			if len(parts) != 2 || parts[0] != "PLAIN" {
				reply("504 só PLAIN")
				continue
			}
			raw, _ := base64.StdEncoding.DecodeString(parts[1])
			fields := strings.Split(string(raw), "\x00")
			if len(fields) == 3 {
				m.User, m.Pass = fields[1], fields[2]
			}
			if m.User == f.user && m.Pass == f.pass {
				reply("235 autenticado")
			} else {
				reply("535 5.7.8 credenciais recusadas")
			}
		case "MAIL":
			addr, _, _ := strings.Cut(strings.TrimPrefix(arg, "FROM:"), " ")
			m.From = strings.Trim(addr, "<>")
			reply("250 ok")
		case "RCPT":
			if f.rcptCode != 0 {
				reply(fmt.Sprintf("%d destinatário recusado", f.rcptCode))
				continue
			}
			m.To = append(m.To, strings.Trim(strings.TrimPrefix(arg, "TO:"), "<>"))
			reply("250 ok")
		case "DATA":
			reply("354 manda")
			data, err := io.ReadAll(tp.DotReader())
			if err != nil {
				return
			}
			m.Data = string(data)
			f.mu.Lock()
			f.mails = append(f.mails, m)
			f.mu.Unlock()
			reply("250 entregue")
		case "QUIT":
			reply("221 tchau")
			return
		default:
			reply("250 ok")
		}
	}
}

// testEnv é um banco migrado com relógio fixo e o serviço de notificações.
type testEnv struct {
	db  *store.DB
	svc *Service
	now *time.Time
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	raw, err := store.Open(ctx, filepath.Join(t.TempDir(), "core.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := store.Migrate(ctx, raw); err != nil {
		t.Fatal(err)
	}
	db := store.New(raw)
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	db.Now = func() time.Time { return now }
	box, err := secrets.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{DB: db, Box: box, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Hostname: "web01",
		Version: "0.3.0", Timeout: 5 * time.Second}
	return &testEnv{db: db, svc: svc, now: &now}
}

func (e *testEnv) advance(d time.Duration) { *e.now = e.now.Add(d) }

// channel grava um canal com o segredo cifrado.
func (e *testEnv) channel(t *testing.T, name, kind string, cfg any, secret string) store.NotificationChannel {
	t.Helper()
	raw, _ := json.Marshal(cfg)
	sealed, err := e.svc.SealSecret(kind, secret)
	if err != nil {
		t.Fatal(err)
	}
	c := store.NotificationChannel{Name: name, Kind: kind, Enabled: true, Config: string(raw), Secret: sealed,
		IncludeDetails: true, CreatedBy: "ana"}
	if err := e.db.CreateNotificationChannel(context.Background(), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *testEnv) rule(t *testing.T, channel int64, event, minSev string, dedup int) {
	t.Helper()
	r := store.NotificationRule{ChannelID: channel, Event: event, MinSeverity: minSev, DedupMinutes: dedup, Enabled: true}
	if err := e.db.CreateNotificationRule(context.Background(), &r); err != nil {
		t.Fatal(err)
	}
}

func (e *testEnv) outbox(t *testing.T) []store.OutboxEntry {
	t.Helper()
	list, err := e.db.ListOutbox(context.Background(), store.OutboxFilter{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// readAll lê o corpo inteiro (para os servidores httptest).
func readAll(r io.Reader) []byte {
	b, _ := io.ReadAll(bufio.NewReader(r))
	return b
}
