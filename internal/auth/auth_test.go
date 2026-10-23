package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guigallina27/vigiahost/internal/store"
)

func TestSenhaArgon2id(t *testing.T) {
	h, err := HashPassword("correta cavalo bateria")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=47104,t=1,p=1$") {
		t.Fatalf("formato: %s", h)
	}
	if ok, _ := VerifyPassword(h, "correta cavalo bateria"); !ok {
		t.Fatal("senha correta recusada")
	}
	if ok, _ := VerifyPassword(h, "errada"); ok {
		t.Fatal("senha errada aceita")
	}
	if _, err := VerifyPassword("$argon2id$v=19$m=99999999,t=1,p=1$YQ$YQ", "x"); err == nil {
		t.Fatal("parâmetros absurdos (negação de serviço) deveriam ser recusados")
	}
	if CheckPassword("curta") == nil || CheckPassword("doze-letras!") != nil {
		t.Fatal("política de comprimento")
	}
}

func TestTOTPRFC6238(t *testing.T) {
	// Vetor do apêndice B da RFC 6238 (SHA-1, segredo "12345678901234567890", T = 59 s → 94287082, 8 dígitos).
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	code, _ := TOTPCode(secret, Step(time.Unix(59, 0)))
	if code != "287082" {
		t.Fatalf("código = %s, esperado 287082 (6 últimos dígitos do vetor)", code)
	}
	now := time.Unix(1_800_000_000, 0)
	prev, _ := TOTPCode(secret, Step(now)-1)
	if step, ok := VerifyTOTP(secret, prev, now); !ok || step != Step(now)-1 {
		t.Fatal("passo anterior deveria valer (relógio atrasado)")
	}
	old, _ := TOTPCode(secret, Step(now)-2)
	if _, ok := VerifyTOTP(secret, old, now); ok {
		t.Fatal("dois passos atrás não vale")
	}
	if !strings.HasPrefix(TOTPURI(secret, "ana"), "otpauth://totp/VigiaHost:ana?") {
		t.Fatal("URI do autenticador")
	}
	m, err := QRMatrix(TOTPURI(secret, "ana"))
	if err != nil || len(m) < 21 || len(m[0]) != len(m) {
		t.Fatalf("matriz do QR: %d %v", len(m), err)
	}
	if NormalizeRecoveryCode(" ABCDE fghjk ") != "abcde-fghjk" {
		t.Fatal("normalização do código de recuperação")
	}
}

type env struct {
	svc  *Service
	now  *time.Time
	logs *bytes.Buffer
	ctx  context.Context
}

func newEnv(t *testing.T) env {
	t.Helper()
	ctx := context.Background()
	raw, err := store.Open(ctx, filepath.Join(t.TempDir(), "a.db"))
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
	logs := &bytes.Buffer{}
	s := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), FailLog: logs,
		Config: Config{Sleep: func(time.Duration) {}}}
	return env{svc: s, now: &now, logs: logs, ctx: ctx}
}

func (e env) totp(t *testing.T, secret string) string {
	t.Helper()
	c, err := TOTPCode(secret, Step(*e.now))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// setupAdmin percorre o primeiro acesso completo e devolve o cookie da sessão completa e o segredo TOTP.
func setupAdmin(t *testing.T, e env) (string, Principal, string) {
	t.Helper()
	tok, err := e.svc.NewFirstAccessToken(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Setup(e.ctx, "vhf_errado", "ana", "Ana", "senha-muito-longa", "10.0.0.1", ""); !errors.Is(err, ErrBadToken) {
		t.Fatalf("token errado: %v", err)
	}
	cookie, p, err := e.svc.Setup(e.ctx, tok, "ana", "Ana", "senha-muito-longa", "10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Stage != store.StageMFASetup {
		t.Fatalf("administrador precisa configurar o segundo fator: %s", p.Stage)
	}
	if _, _, err := e.svc.Setup(e.ctx, tok, "bia", "", "senha-muito-longa", "10.0.0.1", ""); err == nil {
		t.Fatal("token de primeiro acesso não pode ser reusado")
	}
	p, err = e.svc.Authenticate(e.ctx, cookie, "")
	if err != nil {
		t.Fatal(err)
	}
	setup, err := e.svc.BeginMFASetup(e.ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	cookie2, p2, codes, err := e.svc.EnableMFA(e.ctx, p, e.totp(t, setup.Secret), "10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 || p2.Stage != store.StageFull || cookie2 == cookie {
		t.Fatalf("ativação do segundo fator: %d códigos, etapa %s", len(codes), p2.Stage)
	}
	if _, err := e.svc.Authenticate(e.ctx, cookie, ""); err == nil {
		t.Fatal("identificador antigo deveria deixar de valer (troca de sessão)")
	}
	return cookie2, p2, setup.Secret
}

func TestPrimeiroAcessoSegundoFatorEReautenticacao(t *testing.T) {
	e := newEnv(t)
	cookie, p, secret := setupAdmin(t, e)
	if !p.Reauthenticated(*e.now) {
		t.Fatal("ativação do segundo fator conta como reautenticação recente")
	}
	*e.now = e.now.Add(6 * time.Minute)
	p, err := e.svc.Authenticate(e.ctx, cookie, "")
	if err != nil || p.Reauthenticated(*e.now) {
		t.Fatalf("reautenticação vale 5 minutos: %v", err)
	}
	// Login novo: senha e depois o segundo fator.
	*e.now = e.now.Add(time.Minute)
	c1, p1, err := e.svc.Login(e.ctx, "ANA", "senha-muito-longa", "10.0.0.2", "")
	if err != nil || p1.Stage != store.StagePassword {
		t.Fatalf("login: %v %s", err, p1.Stage)
	}
	code := e.totp(t, secret)
	c2, p2, err := e.svc.VerifyMFA(e.ctx, p1, code, "10.0.0.2", "")
	if err != nil || p2.Stage != store.StageFull || c2 == c1 {
		t.Fatalf("segundo fator: %v", err)
	}
	// Mesmo código de novo (outra sessão) não vale.
	_, p3, _ := e.svc.Login(e.ctx, "ana", "senha-muito-longa", "10.0.0.2", "")
	if _, _, err := e.svc.VerifyMFA(e.ctx, p3, code, "10.0.0.2", ""); !errors.Is(err, ErrBadCode) {
		t.Fatalf("código TOTP reusado: %v", err)
	}
	// Reautenticação com senha e código do próximo passo.
	*e.now = e.now.Add(30 * time.Second)
	_, p4, err := e.svc.Reauth(e.ctx, p2, "senha-muito-longa", e.totp(t, secret), "10.0.0.2", "")
	if err != nil || !p4.Reauthenticated(*e.now) {
		t.Fatalf("reautenticação: %v", err)
	}
	if !strings.Contains(e.logs.String(), "vigiahost: login falhou user=ana ip=10.0.0.2 motivo=segundo_fator") {
		t.Fatalf("linha para o fail2ban: %q", e.logs.String())
	}
	if bad, _ := e.svc.DB.VerifyAudit(e.ctx); bad != 0 {
		t.Fatalf("cadeia da auditoria quebrada em %d", bad)
	}
}

func TestBloqueioProgressivoSemRevelarUsuario(t *testing.T) {
	e := newEnv(t)
	setupAdmin(t, e)
	_ = e.svc.DB.ClearThrottle(e.ctx, "user:ana") // a tentativa com token errado no primeiro acesso já contou
	var delays []time.Duration
	e.svc.Config.Sleep = func(d time.Duration) { delays = append(delays, d) }
	for i := 0; i < 10; i++ {
		_, _, err := e.svc.Login(e.ctx, "ana", "errada-errada-errada", "10.0.0.9", "")
		if !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("tentativa %d: %v", i+1, err)
		}
	}
	if len(delays) == 0 || delays[0] != time.Second {
		t.Fatalf("atraso a partir da 5ª falha: %v", delays)
	}
	if _, _, err := e.svc.Login(e.ctx, "ana", "senha-muito-longa", "10.0.0.9", ""); !errors.Is(err, ErrLocked) {
		t.Fatalf("10 falhas deveriam bloquear mesmo com a senha certa: %v", err)
	}
	*e.now = e.now.Add(16 * time.Minute)
	if _, _, err := e.svc.Login(e.ctx, "ana", "senha-muito-longa", "10.0.0.10", ""); err != nil {
		t.Fatalf("bloqueio expira: %v", err)
	}
	if _, _, err := e.svc.Login(e.ctx, "nao-existe", "x", "10.0.0.11", ""); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("usuário inexistente devolve o mesmo erro: %v", err)
	}
}

func TestSessaoExpiraERecuperacaoPeloRoot(t *testing.T) {
	e := newEnv(t)
	cookie, p, _ := setupAdmin(t, e)
	*e.now = e.now.Add(31 * time.Minute)
	if _, err := e.svc.Authenticate(e.ctx, cookie, ""); err == nil {
		t.Fatal("sessão ociosa por mais de 30 minutos deveria expirar")
	}
	tok, err := e.svc.NewResetToken(e.ctx, "ana")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ResetWithToken(e.ctx, tok, "outra-senha-longa", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ResetWithToken(e.ctx, tok, "outra-senha-longa", "10.0.0.1"); !errors.Is(err, ErrBadToken) {
		t.Fatalf("token de recuperação é de uso único: %v", err)
	}
	_, p2, err := e.svc.Login(e.ctx, "ana", "outra-senha-longa", "10.0.0.1", "")
	if err != nil || p2.Stage != store.StageMFASetup {
		t.Fatalf("depois da recuperação, o segundo fator é configurado de novo: %v %s", err, p2.Stage)
	}
	_ = p
}

func TestTokensDeAPI(t *testing.T) {
	e := newEnv(t)
	_, p, _ := setupAdmin(t, e)
	raw, tok, err := e.svc.NewAPIToken(e.ctx, p, "monitoramento", store.RoleReader, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.Authenticate(e.ctx, "", raw)
	if err != nil || got.Role != store.RoleReader || !got.APIToken {
		t.Fatalf("token: %+v %v", got, err)
	}
	if _, err := e.svc.BeginMFASetup(e.ctx, got); err == nil {
		t.Fatal("token de API não mexe no segundo fator")
	}
	auditor := Principal{UserID: p.UserID, Username: "aud", Role: store.RoleAuditor}
	if _, _, err := e.svc.NewAPIToken(e.ctx, auditor, "x", store.RoleOperator, time.Hour); err == nil {
		t.Fatal("auditor não emite token de operador")
	}
	_ = e.svc.DB.RevokeAPIToken(e.ctx, tok.ID)
	if _, err := e.svc.Authenticate(e.ctx, "", raw); err == nil {
		t.Fatal("token revogado")
	}
}
