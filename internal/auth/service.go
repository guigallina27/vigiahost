package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/store"
)

// Erros devolvidos à API (mensagens genéricas: não revelam se o usuário existe).
var (
	ErrBadCredentials = errors.New("usuário ou senha incorretos")
	ErrBadCode        = errors.New("código inválido ou já usado")
	ErrLocked         = errors.New("muitas tentativas; aguarde alguns minutos e tente de novo")
	ErrUnauthorized   = errors.New("sessão ausente ou expirada")
	ErrStage          = errors.New("etapa de login incorreta para esta operação")
	ErrBadToken       = errors.New("token inválido, vencido ou já usado")
)

// Config ajusta sessões e bloqueios; zero usa os valores do ADR-016.
type Config struct {
	Idle      time.Duration // inatividade (30 min)
	Absolute  time.Duration // duração máxima (12 h)
	Reauth    time.Duration // validade da reautenticação (5 min)
	DelayFrom int           // atraso crescente a partir desta falha (5)
	LockAt    int           // bloqueio temporário nesta falha (10)
	LockFor   time.Duration // duração do bloqueio (15 min)
	// MFAForAll exige segundo fator também de leitura e auditor.
	MFAForAll bool
	// Sleep permite aos testes não esperar o atraso.
	Sleep func(time.Duration)
}

func (c *Config) defaults() {
	if c.Idle <= 0 {
		c.Idle = 30 * time.Minute
	}
	if c.Absolute <= 0 {
		c.Absolute = 12 * time.Hour
	}
	if c.Reauth <= 0 {
		c.Reauth = 5 * time.Minute
	}
	if c.DelayFrom <= 0 {
		c.DelayFrom = 5
	}
	if c.LockAt <= 0 {
		c.LockAt = 10
	}
	if c.LockFor <= 0 {
		c.LockFor = 15 * time.Minute
	}
	if c.Sleep == nil {
		c.Sleep = time.Sleep
	}
}

// Service concentra as regras de autenticação.
type Service struct {
	DB     *store.DB
	Logger *slog.Logger
	// FailLog recebe a linha estável de falha de login para o fail2ban/LFD (o journal, pelo stderr).
	FailLog io.Writer
	Config  Config
}

// Principal é quem fez a requisição.
type Principal struct {
	UserID      int64
	Username    string
	DisplayName string
	Role        string
	Stage       string
	SessionHash string
	ReauthUntil *time.Time
	MFAEnabled  bool
	APIToken    bool
	IP          string
}

// Actor é o nome usado na auditoria e no histórico.
func (p Principal) Actor() string {
	if p.APIToken {
		return p.Username + " (token)"
	}
	return p.Username
}

// Reauthenticated indica reautenticação recente (ações sensíveis).
func (p Principal) Reauthenticated(now time.Time) bool {
	return p.ReauthUntil != nil && now.Before(*p.ReauthUntil)
}

func (s *Service) cfg() Config {
	c := s.Config
	c.defaults()
	return c
}

// MFARequired diz se o perfil exige segundo fator.
func (s *Service) MFARequired(role string) bool {
	return role == store.RoleAdmin || role == store.RoleOperator || s.cfg().MFAForAll
}

// NewSession cria a sessão e devolve o valor do cookie.
func (s *Service) newSession(u store.User, stage, ip, ua string, reauth bool) (string, store.Session) {
	now := s.DB.Now()
	tok := RandomToken(32)
	sess := store.Session{IDHash: store.HashToken(tok), UserID: u.ID, Stage: stage, CreatedAt: now, LastSeen: now,
		ExpiresAt: now.Add(s.cfg().Absolute), IP: ip, UserAgent: clipUA(ua)}
	if reauth {
		until := now
		sess.ReauthAt = &until
	}
	return tok, sess
}

func clipUA(ua string) string {
	if len(ua) > 256 {
		return ua[:256]
	}
	return ua
}

func (s *Service) stageFor(u store.User) string {
	switch {
	case u.MFAEnabled():
		return store.StagePassword
	case s.MFARequired(u.Role):
		return store.StageMFASetup
	}
	return store.StageFull
}

// throttleWait confere bloqueio e aplica o atraso progressivo das chaves.
func (s *Service) throttleWait(ctx context.Context, keys ...string) error {
	c := s.cfg()
	now := s.DB.Now()
	worst := 0
	for _, k := range keys {
		t, err := s.DB.GetThrottle(ctx, k)
		if err != nil {
			return err
		}
		if t.LockedUntil != nil && now.Before(*t.LockedUntil) {
			return ErrLocked
		}
		if now.Sub(t.LastFailure) <= c.LockFor {
			worst = max(worst, t.Failures)
		}
	}
	if worst >= c.DelayFrom {
		d := min(time.Second<<(worst-c.DelayFrom), 8*time.Second)
		c.Sleep(d)
	}
	return nil
}

func (s *Service) fail(ctx context.Context, username, ip, reason string) {
	c := s.cfg()
	for _, k := range []string{"user:" + strings.ToLower(username), "ip:" + ip} {
		if _, err := s.DB.RecordFailure(ctx, k, c.LockFor, c.LockAt, c.LockFor); err != nil {
			s.Logger.Error("falha ao registrar tentativa de login", "erro", err)
		}
	}
	if s.FailLog != nil {
		// Formato estável para filtros do fail2ban/LFD: não mudar sem atualizar a documentação.
		_, _ = fmt.Fprintf(s.FailLog, "vigiahost: login falhou user=%s ip=%s motivo=%s\n", sanitizeLog(username), ip, reason)
	}
}

func sanitizeLog(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x21 || r == 0x7f || r == '=' {
			return '_'
		}
		return r
	}, s)
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// Login confere usuário e senha. A sessão criada pode ainda exigir o segundo fator.
func (s *Service) Login(ctx context.Context, username, password, ip, ua string) (string, Principal, error) {
	username = strings.TrimSpace(username)
	if err := s.throttleWait(ctx, "user:"+strings.ToLower(username), "ip:"+ip); err != nil {
		if errors.Is(err, ErrLocked) {
			s.fail(ctx, username, ip, "bloqueado")
		}
		return "", Principal{}, err
	}
	u, err := s.DB.GetUserByName(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		_, _ = VerifyPassword(dummyHash, password)
		s.fail(ctx, username, ip, "senha")
		return "", Principal{}, ErrBadCredentials
	}
	if err != nil {
		return "", Principal{}, err
	}
	ok, err := VerifyPassword(u.PasswordHash, password)
	if err != nil || !ok || u.Disabled {
		s.fail(ctx, username, ip, "senha")
		return "", Principal{}, ErrBadCredentials
	}
	_ = s.DB.ClearThrottle(ctx, "user:"+strings.ToLower(username))
	stage := s.stageFor(u)
	tok, sess := s.newSession(u, stage, ip, ua, stage == store.StageFull)
	if err := s.DB.CreateSession(ctx, sess); err != nil {
		return "", Principal{}, err
	}
	if stage == store.StageFull {
		s.loggedIn(ctx, u, ip)
	}
	return tok, s.principal(u, sess), nil
}

func (s *Service) loggedIn(ctx context.Context, u store.User, ip string) {
	_ = s.DB.ClearThrottle(ctx, "ip:"+ip)
	_ = s.DB.TouchLogin(ctx, u.ID)
	_ = s.DB.Audit(ctx, u.Username, "login", "", "", ip)
}

func (s *Service) principal(u store.User, sess store.Session) Principal {
	p := Principal{UserID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Role: u.Role, Stage: sess.Stage,
		SessionHash: sess.IDHash, MFAEnabled: u.MFAEnabled(), IP: sess.IP}
	if sess.ReauthAt != nil {
		until := sess.ReauthAt.Add(s.cfg().Reauth)
		p.ReauthUntil = &until
	}
	return p
}

// checkSecondFactor aceita código TOTP (sem reuso) ou código de recuperação.
func (s *Service) checkSecondFactor(ctx context.Context, u store.User, code string) error {
	if step, ok := VerifyTOTP(u.TOTPSecret, code, s.DB.Now()); ok {
		if err := s.DB.UseTOTPStep(ctx, u.ID, step); err != nil {
			return ErrBadCode
		}
		return nil
	}
	if rc := NormalizeRecoveryCode(code); rc != "" {
		if err := s.DB.UseRecoveryCode(ctx, u.ID, store.HashToken(rc)); err == nil {
			_ = s.DB.Audit(ctx, u.Username, "recovery_code_used", "", "", "")
			return nil
		}
	}
	return ErrBadCode
}

// VerifyMFA completa o login com o segundo fator e troca o identificador da sessão.
func (s *Service) VerifyMFA(ctx context.Context, p Principal, code, ip, ua string) (string, Principal, error) {
	if p.Stage != store.StagePassword {
		return "", p, ErrStage
	}
	if err := s.throttleWait(ctx, "user:"+strings.ToLower(p.Username), "ip:"+ip); err != nil {
		return "", p, err
	}
	u, err := s.DB.GetUser(ctx, p.UserID)
	if err != nil {
		return "", p, ErrUnauthorized
	}
	if err := s.checkSecondFactor(ctx, u, code); err != nil {
		s.fail(ctx, u.Username, ip, "segundo_fator")
		return "", p, err
	}
	_ = s.DB.ClearThrottle(ctx, "user:"+strings.ToLower(u.Username))
	tok, sess := s.newSession(u, store.StageFull, ip, ua, true)
	if err := s.DB.RotateSession(ctx, p.SessionHash, sess); err != nil {
		return "", p, err
	}
	s.loggedIn(ctx, u, ip)
	return tok, s.principal(u, sess), nil
}

// MFASetup é o que a interface mostra para configurar o aplicativo autenticador.
type MFASetup struct {
	Secret string
	URI    string
	Matrix []string
}

// BeginMFASetup gera um segredo pendente. Na sessão completa (trocar de aparelho) exige reautenticação.
func (s *Service) BeginMFASetup(ctx context.Context, p Principal) (MFASetup, error) {
	if p.APIToken || (p.Stage != store.StageMFASetup && (p.Stage != store.StageFull || !p.Reauthenticated(s.DB.Now()))) {
		return MFASetup{}, ErrStage
	}
	secret := NewTOTPSecret()
	if err := s.DB.SetTOTPPending(ctx, p.UserID, secret); err != nil {
		return MFASetup{}, err
	}
	uri := TOTPURI(secret, p.Username)
	m, err := QRMatrix(uri)
	if err != nil {
		return MFASetup{}, err
	}
	return MFASetup{Secret: secret, URI: uri, Matrix: m}, nil
}

// EnableMFA confirma o segredo pendente com um código, gera os códigos de recuperação e completa a sessão.
func (s *Service) EnableMFA(ctx context.Context, p Principal, code, ip, ua string) (string, Principal, []string, error) {
	if p.APIToken || (p.Stage != store.StageMFASetup && p.Stage != store.StageFull) {
		return "", p, nil, ErrStage
	}
	u, err := s.DB.GetUser(ctx, p.UserID)
	if err != nil {
		return "", p, nil, ErrUnauthorized
	}
	if u.TOTPPending == "" {
		return "", p, nil, ErrStage
	}
	step, ok := VerifyTOTP(u.TOTPPending, code, s.DB.Now())
	if !ok {
		s.fail(ctx, u.Username, ip, "segundo_fator")
		return "", p, nil, ErrBadCode
	}
	codes := NewRecoveryCodes()
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = store.HashToken(c)
	}
	tok, sess := s.newSession(u, store.StageFull, ip, ua, true)
	if err := s.DB.EnableTOTP(ctx, u.ID, step, hashes, p.SessionHash); err != nil {
		return "", p, nil, err
	}
	if err := s.DB.RotateSession(ctx, p.SessionHash, sess); err != nil {
		return "", p, nil, err
	}
	if p.Stage == store.StageMFASetup {
		s.loggedIn(ctx, u, ip)
	}
	_ = s.DB.Audit(ctx, u.Username, "mfa_enabled", u.Username, "", ip)
	u.TOTPSecret = u.TOTPPending
	return tok, s.principal(u, sess), codes, nil
}

// Reauth confirma a identidade para ações sensíveis (senha e, se configurado, segundo fator) e troca o identificador.
func (s *Service) Reauth(ctx context.Context, p Principal, password, code, ip, ua string) (string, Principal, error) {
	if p.APIToken || p.Stage != store.StageFull {
		return "", p, ErrStage
	}
	if err := s.throttleWait(ctx, "user:"+strings.ToLower(p.Username), "ip:"+ip); err != nil {
		return "", p, err
	}
	u, err := s.DB.GetUser(ctx, p.UserID)
	if err != nil {
		return "", p, ErrUnauthorized
	}
	if ok, _ := VerifyPassword(u.PasswordHash, password); !ok {
		s.fail(ctx, u.Username, ip, "reautenticacao")
		return "", p, ErrBadCredentials
	}
	if u.MFAEnabled() {
		if err := s.checkSecondFactor(ctx, u, code); err != nil {
			s.fail(ctx, u.Username, ip, "segundo_fator")
			return "", p, err
		}
	}
	old, err := s.DB.GetSession(ctx, p.SessionHash)
	if err != nil {
		return "", p, ErrUnauthorized
	}
	tok, sess := s.newSession(u, store.StageFull, ip, ua, true)
	sess.CreatedAt, sess.ExpiresAt = old.CreatedAt, old.ExpiresAt // reautenticar não estende a duração máxima
	if err := s.DB.RotateSession(ctx, p.SessionHash, sess); err != nil {
		return "", p, err
	}
	_ = s.DB.Audit(ctx, u.Username, "reauth", "", "", ip)
	return tok, s.principal(u, sess), nil
}

// Authenticate valida o cookie de sessão ou o token de API.
func (s *Service) Authenticate(ctx context.Context, cookie, bearer string) (Principal, error) {
	now := s.DB.Now()
	if bearer != "" {
		t, err := s.DB.LookupAPIToken(ctx, store.HashToken(bearer))
		if err != nil {
			return Principal{}, ErrUnauthorized
		}
		return Principal{UserID: t.UserID, Username: t.Username, Role: t.Role, Stage: store.StageFull, APIToken: true}, nil
	}
	if cookie == "" {
		return Principal{}, ErrUnauthorized
	}
	sess, err := s.DB.GetSession(ctx, store.HashToken(cookie))
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	c := s.cfg()
	if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeen) > c.Idle {
		_ = s.DB.DeleteSession(ctx, sess.IDHash)
		return Principal{}, ErrUnauthorized
	}
	u, err := s.DB.GetUser(ctx, sess.UserID)
	if err != nil || u.Disabled {
		_ = s.DB.DeleteSession(ctx, sess.IDHash)
		return Principal{}, ErrUnauthorized
	}
	if now.Sub(sess.LastSeen) > time.Minute {
		_ = s.DB.TouchSession(ctx, sess.IDHash)
	}
	return s.principal(u, sess), nil
}

// Logout encerra a sessão.
func (s *Service) Logout(ctx context.Context, p Principal) error {
	if p.SessionHash == "" {
		return nil
	}
	_ = s.DB.Audit(ctx, p.Username, "logout", "", "", p.IP)
	return s.DB.DeleteSession(ctx, p.SessionHash)
}

// ChangePassword troca a própria senha (confirma a atual) e encerra as outras sessões.
func (s *Service) ChangePassword(ctx context.Context, p Principal, current, next string) error {
	if p.APIToken || p.Stage != store.StageFull {
		return ErrStage
	}
	u, err := s.DB.GetUser(ctx, p.UserID)
	if err != nil {
		return ErrUnauthorized
	}
	if ok, _ := VerifyPassword(u.PasswordHash, current); !ok {
		s.fail(ctx, u.Username, p.IP, "troca_de_senha")
		return ErrBadCredentials
	}
	if err := CheckPassword(next); err != nil {
		return err
	}
	h, err := HashPassword(next)
	if err != nil {
		return err
	}
	if err := s.DB.SetPassword(ctx, u.ID, h, p.SessionHash); err != nil {
		return err
	}
	return s.DB.Audit(ctx, u.Username, "password_changed", u.Username, "", p.IP)
}

// CheckUsername valida o nome de usuário.
func CheckUsername(name string) error {
	if len(name) < 2 || len(name) > 64 {
		return errors.New("o nome de usuário precisa ter de 2 a 64 caracteres")
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '-' && r != '_' && r != '@' {
			return errors.New("use apenas letras sem acento, números, ponto, hífen, sublinhado ou arroba no nome de usuário")
		}
	}
	return nil
}

// Setup cria o primeiro administrador com o token de primeiro acesso e já abre a sessão (falta o segundo fator).
func (s *Service) Setup(ctx context.Context, token, username, display, password, ip, ua string) (string, Principal, error) {
	if err := s.throttleWait(ctx, "ip:"+ip); err != nil {
		return "", Principal{}, err
	}
	if err := CheckUsername(username); err != nil {
		return "", Principal{}, err
	}
	if err := CheckPassword(password); err != nil {
		return "", Principal{}, err
	}
	h, err := HashPassword(password)
	if err != nil {
		return "", Principal{}, err
	}
	u := store.User{Username: username, DisplayName: strings.TrimSpace(display), PasswordHash: h}
	if err := s.DB.CreateFirstAdmin(ctx, store.HashToken(strings.TrimSpace(token)), &u); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(ctx, username, ip, "token_primeiro_acesso")
			return "", Principal{}, ErrBadToken
		}
		return "", Principal{}, err
	}
	_ = s.DB.Audit(ctx, u.Username, "first_admin_created", u.Username, "", ip)
	tok, sess := s.newSession(u, s.stageFor(u), ip, ua, false)
	if err := s.DB.CreateSession(ctx, sess); err != nil {
		return "", Principal{}, err
	}
	return tok, s.principal(u, sess), nil
}

// ResetWithToken redefine a senha com o token gerado pelo root (o segundo fator é configurado de novo no login).
func (s *Service) ResetWithToken(ctx context.Context, token, password, ip string) error {
	if err := s.throttleWait(ctx, "ip:"+ip); err != nil {
		return err
	}
	if err := CheckPassword(password); err != nil {
		return err
	}
	h, err := HashPassword(password)
	if err != nil {
		return err
	}
	uid, err := s.DB.ResetWithToken(ctx, store.HashToken(strings.TrimSpace(token)), h)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(ctx, "-", ip, "token_recuperacao")
			return ErrBadToken
		}
		return err
	}
	u, _ := s.DB.GetUser(ctx, uid)
	return s.DB.Audit(ctx, u.Username, "password_reset_with_token", u.Username, "", ip)
}

// NewFirstAccessToken gera o token de primeiro acesso (válido por 24 h); só faz sentido sem usuários.
func (s *Service) NewFirstAccessToken(ctx context.Context) (string, error) {
	n, err := s.DB.CountUsers(ctx)
	if err != nil {
		return "", err
	}
	if n > 0 {
		return "", errors.New("já existem usuários; use a recuperação de acesso")
	}
	tok := "vhf_" + RandomToken(24)
	return tok, s.DB.CreateOneTimeToken(ctx, store.HashToken(tok), "first_access", nil, 24*time.Hour)
}

// NewResetToken gera o token de recuperação de um usuário (15 minutos), pedido pelo root no terminal.
func (s *Service) NewResetToken(ctx context.Context, username string) (string, error) {
	u, err := s.DB.GetUserByName(ctx, username)
	if err != nil {
		return "", err
	}
	tok := "vhr_" + RandomToken(24)
	if err := s.DB.CreateOneTimeToken(ctx, store.HashToken(tok), "reset", &u.ID, 15*time.Minute); err != nil {
		return "", err
	}
	_ = s.DB.Audit(ctx, "root", "reset_token_issued", u.Username, "terminal do servidor", "")
	return tok, nil
}

// NewAPIToken cria um token de automação para o usuário, com perfil igual ou menor que o dele.
func (s *Service) NewAPIToken(ctx context.Context, p Principal, name, role string, ttl time.Duration) (string, store.APIToken, error) {
	// Mesmo perfil do usuário ou leitura; só o administrador emite qualquer perfil (auditor não vira operador etc.).
	if !store.ValidRole(role) || (role != p.Role && role != store.RoleReader && p.Role != store.RoleAdmin) {
		return "", store.APIToken{}, errors.New("perfil do token não pode ser maior que o do usuário")
	}
	if ttl <= 0 || ttl > 366*24*time.Hour {
		return "", store.APIToken{}, errors.New("validade do token entre 1 e 365 dias")
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return "", store.APIToken{}, errors.New("informe um nome de até 64 caracteres para o token")
	}
	raw := "vht_" + RandomToken(32)
	t := store.APIToken{Name: name, UserID: p.UserID, Username: p.Username, Role: role, Prefix: raw[:10],
		ExpiresAt: s.DB.Now().Add(ttl)}
	if err := s.DB.CreateAPIToken(ctx, &t, store.HashToken(raw)); err != nil {
		return "", t, err
	}
	_ = s.DB.Audit(ctx, p.Actor(), "api_token_created", name, "perfil "+role, p.IP)
	return raw, t, nil
}
