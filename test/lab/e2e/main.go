// Comando e2e: teste de ponta a ponta real do VigiaHost no laboratório, contra o pacote instalado e ativo pelo systemd
// (core em http://127.0.0.1:8743, executor root, ClamAV e YARA-X reais). Percorre a API como a interface faria:
// primeiro acesso com o token do terminal e a caixa "não sou um robô" (ALTCHA), segundo fator TOTP, varreduras de
// arquivos (completa e incremental) sobre os corpus, inspeção de processos com um processo sem arquivo (memfd),
// ciclo de vida do achado, exceção com reautenticação, agendamento, cópia do banco, token de API e auditoria.
//
// Repetível: na primeira execução cria o administrador e2e-admin e grava usuário, senha, segredo TOTP e códigos de
// recuperação em /root/.vigiahost-e2e.json (0600); nas seguintes, com o banco já tendo usuários, reusa esse arquivo.
// Nada secreto é impresso (senha, segredo TOTP, token de primeiro acesso, tokens de API).
//
// Use por test/lab/test-e2e.sh, que compila este programa, sobe o processo de teste memfd e chama:
//
//	e2e -memfd-pid PID [-base URL] [-creds ARQUIVO] [-corpus DIR] [-run-timeout 15m] [-mode auto|setup|reuse] [-essential-only]
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) usa HMAC-SHA1, o mesmo do servidor
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"

	"github.com/guigallina27/vigiahost/internal/api"
)

const (
	sessionCookie = "__Host-vh_session"
	e2eUser       = "e2e-admin"
	// e2eTag marca o que o teste cria (exceções, agendamentos, tokens, chaves de idempotência); só isso é limpo.
	e2eTag = "e2e-vigiahost"

	sigControl = "vigiahost_controle_positivo"
	sigEICAR   = "Eicar-Test-Signature"
	sigMemfd   = "processo.executavel_memfd"
	memfdName  = "memfd:vigiahost-controle"

	engineYARA  = "yara-x"
	engineClam  = "clamav"
	profileName = "padrao"
)

// Arquivos do corpus positivo que precisam ser detectados mesmo com -essential-only.
var essentialEntries = map[string]bool{"eicar/eicar.com": true, "marcador/marcador.txt": true}

type config struct {
	base            string
	credsPath       string
	firstAccessFile string
	corpus          string
	runTimeout      time.Duration
	memfdPID        int
	essentialOnly   bool
	mode            string
}

// credentials fica em arquivo 0600 do root para a próxima execução reusar o administrador do teste.
type credentials struct {
	BaseURL       string    `json:"base_url"`
	Username      string    `json:"username"`
	Password      string    `json:"password"`
	TOTPSecret    string    `json:"totp_secret,omitempty"`
	RecoveryCodes []string  `json:"recovery_codes,omitempty"`
	LastTOTPStep  int64     `json:"last_totp_step,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type tester struct {
	cfg         config
	hc          *http.Client
	cookie      string
	creds       credentials
	reauthUntil time.Time
	reauths     int
	auditStart  int64
}

type reqOpts struct {
	bearer string
	idem   string
}

type response struct {
	method, path string
	status       int
	body         []byte
}

// scanResult guarda o que a varredura completa encontrou, para as etapas seguintes.
type scanResult struct {
	runID      string
	ids        map[int64]bool
	eicarID    int64 // achado do ClamAV no eicar/eicar.com
	markerID   int64 // achado do YARA-X no marcador/marcador.txt
	positivos  string
	benigno    string
	openBefore int64
}

type manifestEntry struct {
	Path    string `json:"path"`
	PathHex string `json:"path_hex"`
	Expect  struct {
		ClamAV    string   `json:"clamav"`
		YARA      []string `json:"yara"`
		Heuristic bool     `json:"heuristic"`
	} `json:"expect"`
}

type manifest struct {
	Kind    string          `json:"kind"`
	Entries []manifestEntry `json:"entries"`
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.base, "base", "http://127.0.0.1:8743", "endereço do core (precisa ser o endereço local ou HTTPS)")
	flag.StringVar(&cfg.credsPath, "creds", "/root/.vigiahost-e2e.json", "arquivo 0600 com as credenciais do administrador do teste")
	flag.StringVar(&cfg.firstAccessFile, "first-access-file", "/var/lib/vigiahost/first-access-token", "token de primeiro acesso")
	flag.StringVar(&cfg.corpus, "corpus", "/var/tmp/corpus", "diretório com positivos/ e benigno/")
	flag.DurationVar(&cfg.runTimeout, "run-timeout", 15*time.Minute, "prazo de cada execução (varredura ou inspeção)")
	flag.IntVar(&cfg.memfdPID, "memfd-pid", 0, "PID do processo de teste que roda de memfd (test/lab/memfdrun)")
	flag.BoolVar(&cfg.essentialOnly, "essential-only", false,
		"exige só o EICAR e o marcador.txt; as demais detecções do manifesto viram aviso")
	flag.StringVar(&cfg.mode, "mode", "auto",
		"auto: primeiro acesso se o banco não tiver usuários, senão reusa as credenciais; setup ou reuse forçam um dos dois")
	flag.Parse()
	cfg.base = strings.TrimRight(cfg.base, "/")
	switch cfg.mode {
	case "auto", "setup", "reuse":
	default:
		fatalf("-mode deve ser auto, setup ou reuse")
	}
	if cfg.memfdPID <= 0 {
		fatalf("informe -memfd-pid com o PID do processo de teste memfd (test/lab/test-e2e.sh faz isso)")
	}
	if os.Geteuid() != 0 {
		fatalf("rode como root: o teste lê o token de primeiro acesso e grava %s", cfg.credsPath)
	}

	t := &tester{cfg: cfg, hc: &http.Client{Timeout: 90 * time.Second}}
	pos, ben := t.checkCorpus()
	t.stepHealth()
	t.stepAuth()
	t.stepEngines()
	t.cleanupLeftovers()
	t.auditStart = t.lastAuditID()
	t.reauths = 0 // a auditoria confere só as reautenticações feitas depois deste ponto
	sr := t.stepFileScan(pos, ben)
	t.stepIncremental(sr)
	t.stepProcesses()
	t.stepFindingLifecycle(sr)
	t.stepSchedule(ben)
	t.stepBackup()
	t.stepAPIToken()
	t.stepAudit()
	t.stepLogout()
	fmt.Println("E2E APROVADO")
}

// ---------------------------------------------------------------------------------------------------------------
// Saída

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "FALHA: "+format+"\n", a...)
	os.Exit(1)
}

func ok(format string, a ...any)   { fmt.Printf("ok: "+format+"\n", a...) }
func info(format string, a ...any) { fmt.Printf("  - "+format+"\n", a...) }
func warn(format string, a ...any) { fmt.Printf("aviso: "+format+"\n", a...) }

// ---------------------------------------------------------------------------------------------------------------
// HTTP

func (t *tester) send(method, p string, body any, o reqOpts) response {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			fatalf("%s %s: corpo não serializado: %v", method, p, err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, t.cfg.base+p, rd)
	if err != nil {
		fatalf("%s %s: %v", method, p, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	// O cookie __Host- vem com Secure; o core aceita sessão em HTTP só pelo endereço local, e o cookiejar da
	// biblioteca padrão não devolveria um cookie Secure por HTTP. Por isso o cookie é guardado e enviado à mão.
	if o.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+o.bearer)
	} else if t.cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: t.cookie})
	}
	if o.idem != "" {
		req.Header.Set("Idempotency-Key", o.idem)
	}
	resp, err := t.hc.Do(req)
	if err != nil {
		fatalf("%s %s: %v", method, p, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		fatalf("%s %s: resposta não lida: %v", method, p, err)
	}
	if o.bearer == "" {
		t.absorbCookies(resp)
	}
	return response{method: method, path: p, status: resp.StatusCode, body: data}
}

// absorbCookies guarda o cookie de sessão (o core troca o identificador no login, no segundo fator e na
// reautenticação) e confere os atributos exigidos pelo ADR-016.
func (t *tester) absorbCookies(resp *http.Response) {
	for _, c := range resp.Cookies() {
		if c.Name != sessionCookie {
			continue
		}
		if c.MaxAge < 0 || c.Value == "" {
			t.cookie = ""
			continue
		}
		if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
			fatalf("cookie de sessão sem os atributos exigidos (Secure, HttpOnly, SameSite=Strict, Path=/, sem Domain)")
		}
		t.cookie = c.Value
	}
}

// describe resume a resposta de erro sem despejar o corpo inteiro.
func (r response) describe() string {
	var e api.Error
	if json.Unmarshal(r.body, &e) == nil && e.Error != "" {
		code := ""
		if e.Code != nil {
			code = " [" + *e.Code + "]"
		}
		return fmt.Sprintf("HTTP %d%s: %s", r.status, code, e.Error)
	}
	b := strings.TrimSpace(string(r.body))
	if len(b) > 300 {
		b = b[:300] + "..."
	}
	return fmt.Sprintf("HTTP %d: %s", r.status, b)
}

func (r response) errCode() string {
	var e api.Error
	if json.Unmarshal(r.body, &e) == nil && e.Code != nil {
		return *e.Code
	}
	return ""
}

// decode lê a resposta recusando campos fora do contrato (additionalProperties: false).
func (r response) decode(out any) {
	dec := json.NewDecoder(bytes.NewReader(r.body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		fatalf("%s %s: resposta fora do contrato (HTTP %d): %v", r.method, r.path, r.status, err)
	}
}

// call faz a requisição e exige o código esperado; out != nil decodifica a resposta.
func (t *tester) call(method, p string, body any, o reqOpts, want int, out any) response {
	r := t.send(method, p, body, o)
	if r.status != want {
		fatalf("%s %s: esperado HTTP %d, recebido %s", method, p, want, r.describe())
	}
	if out != nil {
		r.decode(out)
	}
	return r
}

func (t *tester) get(p string, out any) {
	t.call(http.MethodGet, p, nil, reqOpts{}, http.StatusOK, out)
}

// ---------------------------------------------------------------------------------------------------------------
// Credenciais, TOTP e ALTCHA

func (t *tester) saveCreds() {
	b, err := json.MarshalIndent(t.creds, "", "  ")
	if err != nil {
		fatalf("credenciais não serializadas: %v", err)
	}
	tmp := t.cfg.credsPath + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		fatalf("credenciais não gravadas em %s: %v", tmp, err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		fatalf("permissão das credenciais: %v", err)
	}
	if err := os.Rename(tmp, t.cfg.credsPath); err != nil {
		fatalf("credenciais não gravadas em %s: %v", t.cfg.credsPath, err)
	}
}

func (t *tester) loadCreds() {
	st, err := os.Stat(t.cfg.credsPath)
	if errors.Is(err, fs.ErrNotExist) {
		fatalf("o banco já tem usuários, mas %s não existe. Use o arquivo gravado na primeira execução deste teste "+
			"ou reinstale o pacote (com -purge) para um primeiro acesso novo", t.cfg.credsPath)
	}
	if err != nil {
		fatalf("credenciais: %v", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		fatalf("%s com permissão %o; deixe 0600 (chmod 600) antes de reusar", t.cfg.credsPath, st.Mode().Perm())
	}
	data, err := os.ReadFile(t.cfg.credsPath)
	if err != nil {
		fatalf("credenciais: %v", err)
	}
	if err := json.Unmarshal(data, &t.creds); err != nil || t.creds.Username == "" || t.creds.Password == "" {
		fatalf("%s ilegível ou incompleto", t.cfg.credsPath)
	}
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		fatalf("gerador aleatório: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		fatalf("gerador aleatório: %v", err)
	}
	return hex.EncodeToString(b)
}

// totpCode implementa o RFC 6238 com os parâmetros do VigiaHost (SHA-1, 6 dígitos, passo de 30 s).
func totpCode(secret string, step int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		fatalf("segredo TOTP ilegível nas credenciais")
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // passo de tempo, sempre positivo
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// nextTOTP devolve o código de um passo ainda não usado: o core recusa reuso (o passo precisa ser maior que o
// último aceito), então espera o próximo passo de 30 s quando preciso. O passo usado fica gravado nas credenciais.
func (t *tester) nextTOTP() string {
	if t.creds.TOTPSecret == "" {
		fatalf("sem segredo TOTP nas credenciais (%s)", t.cfg.credsPath)
	}
	for {
		now := time.Now()
		step := now.Unix() / 30
		if step > t.creds.LastTOTPStep {
			t.creds.LastTOTPStep = step
			t.saveCreds()
			return totpCode(t.creds.TOTPSecret, step)
		}
		wait := time.Unix((step+1)*30, 0).Sub(now) + 500*time.Millisecond
		info("aguardando %.0f s pelo próximo código TOTP (o core recusa reuso)", wait.Seconds())
		time.Sleep(wait)
	}
}

func (t *tester) solveCaptcha() string {
	r := t.call(http.MethodGet, "/api/v1/auth/challenge", nil, reqOpts{}, http.StatusOK, nil)
	var ch altcha.Challenge
	if err := json.Unmarshal(r.body, &ch); err != nil || ch.Signature == "" {
		fatalf("desafio ALTCHA ilegível: %v", err)
	}
	sol, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{Challenge: ch, DeriveKey: altcha.DeriveKeyPBKDF2()})
	if err != nil || sol == nil {
		fatalf("desafio ALTCHA não resolvido: %v", err)
	}
	b, err := json.Marshal(altcha.Payload{Challenge: ch, Solution: *sol})
	if err != nil {
		fatalf("solução ALTCHA não serializada: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (t *tester) track(s api.Session) {
	if s.ReauthUntil != nil {
		t.reauthUntil = *s.ReauthUntil
	}
}

func stage(s api.Session) string {
	if s.Stage == nil {
		return ""
	}
	return string(*s.Stage)
}

// ensureReauth reautentica (senha + TOTP) quando a reautenticação vale por menos de 2 minutos.
func (t *tester) ensureReauth(why string) {
	if time.Until(t.reauthUntil) > 2*time.Minute {
		return
	}
	code := t.nextTOTP()
	var s api.Session
	t.call(http.MethodPost, "/api/v1/auth/reauth", api.ReauthRequest{Password: t.creds.Password, Code: &code},
		reqOpts{}, http.StatusOK, &s)
	if s.ReauthUntil == nil || !s.ReauthUntil.After(time.Now()) {
		fatalf("reautenticação aceita sem prazo válido (reauth_until)")
	}
	t.track(s)
	t.reauths++
	info("reautenticado com senha e TOTP para %s (vale até %s)", why, s.ReauthUntil.Local().Format("15:04:05"))
}

// ---------------------------------------------------------------------------------------------------------------
// Etapas

func (t *tester) checkCorpus() (string, string) {
	pos, ben := path.Join(t.cfg.corpus, "positivos"), path.Join(t.cfg.corpus, "benigno")
	for _, d := range []string{pos, ben} {
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			fatalf("corpus ausente: %s (gere com test/corpus/gencorpus)", d)
		}
	}
	m := loadManifest(pos)
	ok("pré-requisitos: corpus em %s (manifesto dos positivos com %d arquivos)", t.cfg.corpus, len(m.Entries))
	return pos, ben
}

func loadManifest(dir string) manifest {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		fatalf("manifesto dos positivos: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil || m.Kind != "positivos" || len(m.Entries) == 0 {
		fatalf("manifesto dos positivos ilegível ou de outro tipo (%v)", err)
	}
	return m
}

func (t *tester) stepHealth() {
	r := t.send(http.MethodGet, "/api/v1/health", nil, reqOpts{})
	if r.status != http.StatusOK && r.status != http.StatusServiceUnavailable {
		fatalf("GET /api/v1/health: %s", r.describe())
	}
	var h api.Health
	r.decode(&h)
	if r.status != http.StatusOK || h.Status != "ok" || !h.Executor.Connected {
		reason := ""
		if h.Executor.Error != nil {
			reason = *h.Executor.Error
		}
		fatalf("saúde: core %s com status %s e executor desconectado (%s)", h.Version, h.Status, reason)
	}
	execVer, proto, sys := "?", "?", ""
	if h.Executor.Version != nil {
		execVer = *h.Executor.Version
	}
	if h.Executor.Protocol != nil {
		proto = *h.Executor.Protocol
	}
	if c := h.Executor.System; c != nil {
		sys = fmt.Sprintf(", %s, kernel %s, %s, systemd=%v, cgroup v2=%v", c.DistroName, c.Kernel, c.Arch, c.Systemd, c.CgroupV2)
	}
	ok("saúde: core %s, executor %s conectado (protocolo %s%s)", h.Version, execVer, proto, sys)
}

func (t *tester) session() api.Session {
	var s api.Session
	t.get("/api/v1/auth/session", &s)
	return s
}

func (t *tester) stepAuth() {
	s := t.session()
	if !s.SecureTransport {
		fatalf("o core não considera %s transporte seguro; use o endereço local (127.0.0.1) ou HTTPS", t.cfg.base)
	}
	switch {
	case s.SetupRequired && t.cfg.mode != "reuse":
		t.firstAccess()
		t.setupMFA()
		// Novo login, agora exigindo o código do segundo fator.
		t.logout()
		t.login()
	case s.SetupRequired:
		fatalf("-mode reuse, mas o banco não tem usuários (primeiro acesso pendente)")
	case t.cfg.mode == "setup":
		fatalf("-mode setup, mas o banco já tem usuários; o primeiro acesso já foi feito")
	default:
		t.loadCreds()
		ok("banco com usuários: reusando as credenciais de %s (usuário %s)", t.cfg.credsPath, t.creds.Username)
		t.login()
	}
	cur := t.session()
	if !cur.Authenticated || stage(cur) != "full" || cur.User == nil || cur.User.Username != t.creds.Username ||
		cur.User.Role != "admin" || !cur.User.MfaEnabled {
		fatalf("sessão depois do login não está completa como administrador com segundo fator (autenticada=%v, etapa %q)",
			cur.Authenticated, stage(cur))
	}
	left := -1
	if cur.User.RecoveryCodesLeft != nil {
		left = *cur.User.RecoveryCodesLeft
	}
	ok("sessão completa: %s (admin, segundo fator ativo, %d códigos de recuperação restantes)", cur.User.Username, left)
}

func (t *tester) firstAccess() {
	raw, err := os.ReadFile(t.cfg.firstAccessFile)
	if err != nil {
		fatalf("primeiro acesso pendente, mas o token não foi lido de %s: %v (veja: vigiahost first-access)",
			t.cfg.firstAccessFile, err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		fatalf("token de primeiro acesso vazio em %s", t.cfg.firstAccessFile)
	}
	// Grava antes de criar o usuário: se algo falhar depois, a próxima execução ainda tem a senha.
	t.creds = credentials{BaseURL: t.cfg.base, Username: e2eUser, Password: randomToken(32), CreatedAt: time.Now().UTC()}
	t.saveCreds()

	// Sem a caixa "não sou um robô" o token nem é conferido.
	display := "Teste de ponta a ponta"
	r := t.send(http.MethodPost, "/api/v1/auth/setup", api.SetupRequest{Token: token, Username: e2eUser,
		DisplayName: &display, Password: t.creds.Password, Altcha: ""}, reqOpts{})
	if r.status != http.StatusBadRequest || r.errCode() != "captcha_failed" {
		fatalf("primeiro acesso sem ALTCHA deveria ser recusado com captcha_failed: %s", r.describe())
	}
	var s api.Session
	t.call(http.MethodPost, "/api/v1/auth/setup", api.SetupRequest{Token: token, Username: e2eUser, DisplayName: &display,
		Password: t.creds.Password, Altcha: t.solveCaptcha()}, reqOpts{}, http.StatusOK, &s)
	if s.Authenticated || stage(s) != "mfa_setup" || t.cookie == "" {
		fatalf("depois do primeiro acesso a sessão deveria aguardar a configuração do segundo fator (etapa %q)", stage(s))
	}
	if _, err := os.Stat(t.cfg.firstAccessFile); !errors.Is(err, fs.ErrNotExist) {
		fatalf("o arquivo do token de primeiro acesso deveria ter sido apagado depois do uso (%s)", t.cfg.firstAccessFile)
	}
	ok("primeiro acesso: administrador %s criado com o token do terminal e ALTCHA; token apagado; credenciais em %s (0600)",
		e2eUser, t.cfg.credsPath)
}

func (t *tester) setupMFA() {
	r := t.send(http.MethodGet, "/api/v1/overview", nil, reqOpts{})
	if r.status != http.StatusUnauthorized || r.errCode() != "mfa_setup_required" {
		fatalf("sem segundo fator o painel deveria responder 401 mfa_setup_required: %s", r.describe())
	}
	var setup api.MfaSetup
	t.call(http.MethodPost, "/api/v1/auth/mfa/setup", nil, reqOpts{}, http.StatusOK, &setup)
	if setup.Secret == "" || !strings.HasPrefix(setup.Uri, "otpauth://totp/") || len(setup.Matrix) == 0 {
		fatalf("configuração do segundo fator incompleta (segredo, otpauth:// ou QR ausente)")
	}
	t.creds.TOTPSecret = setup.Secret
	t.saveCreds()
	var en api.MfaEnabled
	t.call(http.MethodPost, "/api/v1/auth/mfa/enable", api.CodeRequest{Code: t.nextTOTP()}, reqOpts{}, http.StatusOK, &en)
	if !en.Session.Authenticated || len(en.RecoveryCodes) != 10 {
		fatalf("segundo fator não ativado (autenticada=%v, %d códigos de recuperação)", en.Session.Authenticated, len(en.RecoveryCodes))
	}
	t.track(en.Session)
	t.creds.RecoveryCodes = en.RecoveryCodes
	t.saveCreds()
	ok("segundo fator TOTP ativo; %d códigos de recuperação guardados em %s", len(en.RecoveryCodes), t.cfg.credsPath)
}

func (t *tester) logout() {
	t.call(http.MethodPost, "/api/v1/auth/logout", nil, reqOpts{}, http.StatusNoContent, nil)
	if t.cookie != "" {
		fatalf("logout não apagou o cookie de sessão")
	}
	t.reauthUntil = time.Time{}
}

// login faz usuário + senha + ALTCHA e completa com o código TOTP (mfa/verify).
func (t *tester) login() {
	var s api.Session
	r := t.send(http.MethodPost, "/api/v1/auth/login", api.LoginRequest{Username: t.creds.Username,
		Password: t.creds.Password, Altcha: t.solveCaptcha()}, reqOpts{})
	if r.status != http.StatusOK {
		fatalf("login de %s: %s", t.creds.Username, r.describe())
	}
	r.decode(&s)
	switch stage(s) {
	case "password":
	case "mfa_setup":
		// Execução anterior interrompida antes de ativar o segundo fator.
		warn("o segundo fator do %s não estava ativo; configurando de novo", t.creds.Username)
		t.setupMFA()
		t.logout()
		t.login()
		return
	default:
		fatalf("login de administrador deveria exigir o segundo fator; etapa %q", stage(s))
	}
	r = t.send(http.MethodGet, "/api/v1/overview", nil, reqOpts{})
	if r.status != http.StatusUnauthorized || r.errCode() != "mfa_required" {
		fatalf("antes do código TOTP o painel deveria responder 401 mfa_required: %s", r.describe())
	}
	t.call(http.MethodPost, "/api/v1/auth/mfa/verify", api.CodeRequest{Code: t.nextTOTP()}, reqOpts{}, http.StatusOK, &s)
	if !s.Authenticated || stage(s) != "full" {
		fatalf("código TOTP aceito, mas a sessão não ficou completa (etapa %q)", stage(s))
	}
	t.track(s)
	ok("login com ALTCHA + senha, painel bloqueado até o código, segundo fator (mfa/verify) aceito")
}

func (t *tester) stepEngines() {
	var es api.EngineStatus
	t.get("/api/v1/engines", &es)
	if es.ExecutorError != nil {
		fatalf("motores: executor respondeu com erro: %s", *es.ExecutorError)
	}
	var parts []string
	for _, id := range []string{engineYARA, engineClam} {
		e := findEngine(es.Engines, id)
		if e == nil {
			fatalf("motor %s ausente em /engines", id)
		}
		detail := deref(e.Detail)
		if e.State == "unavailable" {
			fatalf("motor %s indisponível: %s", id, detail)
		}
		if e.State == "degraded" {
			warn("motor %s degradado: %s", id, detail)
		}
		desc := fmt.Sprintf("%s %s (%s", e.Name, deref(e.Version), e.State)
		if e.Mode != nil {
			desc += ", modo " + *e.Mode
		}
		if e.SignaturesVersion != nil {
			desc += ", assinaturas " + *e.SignaturesVersion
		}
		if st := e.LastSelftest; st != nil {
			desc += fmt.Sprintf(", último autoteste %s", passFail(st.Passed))
		}
		parts = append(parts, desc+")")
	}
	ok("motores: %s", strings.Join(parts, "; "))
}

func findEngine(list []api.EngineHealth, id string) *api.EngineHealth {
	for i := range list {
		if string(list[i].Id) == id {
			return &list[i]
		}
	}
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func passFail(b bool) string {
	if b {
		return "aprovado"
	}
	return "reprovado"
}

// cleanupLeftovers remove o que uma execução anterior interrompida deixou (só itens marcados com e2eTag).
func (t *tester) cleanupLeftovers() {
	n := 0
	var excs []api.Exception
	t.get("/api/v1/exceptions", &excs)
	for _, e := range excs {
		if strings.HasPrefix(e.Reason, e2eTag) {
			t.ensureReauth("revogar exceção deixada por execução anterior")
			t.call(http.MethodDelete, fmt.Sprintf("/api/v1/exceptions/%d", e.Id), nil, reqOpts{}, http.StatusNoContent, nil)
			n++
		}
	}
	var scs []api.Schedule
	t.get("/api/v1/schedules", &scs)
	for _, sc := range scs {
		if strings.HasPrefix(sc.Name, e2eTag) {
			t.call(http.MethodDelete, fmt.Sprintf("/api/v1/schedules/%d", sc.Id), nil, reqOpts{}, http.StatusNoContent, nil)
			n++
		}
	}
	var toks []api.ApiToken
	t.get("/api/v1/tokens", &toks)
	for _, tk := range toks {
		if strings.HasPrefix(tk.Name, e2eTag) && tk.RevokedAt == nil {
			t.call(http.MethodDelete, fmt.Sprintf("/api/v1/tokens/%d", tk.Id), nil, reqOpts{}, http.StatusNoContent, nil)
			n++
		}
	}
	if n > 0 {
		ok("restos de execução anterior do teste removidos: %d item(ns)", n)
	}
}

func (t *tester) lastAuditID() int64 {
	var page api.AuditPage
	t.get("/api/v1/audit?limit=1", &page)
	if len(page.Entries) == 0 {
		return 0
	}
	return page.Entries[0].Id
}

func (t *tester) openTotal() int64 {
	var ov api.Overview
	t.get("/api/v1/overview", &ov)
	return ov.OpenFindings.Total
}

// createRun enfileira a execução e confere que repetir a Idempotency-Key devolve a mesma execução.
func (t *tester) createRun(body api.RunCreate, label string) api.Run {
	key := e2eTag + "-" + randHex(8)
	var run api.Run
	t.call(http.MethodPost, "/api/v1/runs", body, reqOpts{idem: key}, http.StatusCreated, &run)
	if string(run.Kind) != string(body.Kind) || run.RequestedBy != t.creds.Username {
		fatalf("%s criada com tipo %s por %s", label, run.Kind, run.RequestedBy)
	}
	r := t.send(http.MethodPost, "/api/v1/runs", body, reqOpts{idem: key})
	if r.status != http.StatusCreated && r.status != http.StatusOK {
		fatalf("%s: repetição com a mesma Idempotency-Key: %s", label, r.describe())
	}
	var dup api.Run
	r.decode(&dup)
	if dup.Id != run.Id {
		fatalf("%s: a mesma Idempotency-Key criou outra execução (%s e %s)", label, run.Id, dup.Id)
	}
	return run
}

func terminal(st api.RunStatus) bool {
	switch st {
	case "queued", "reserved", "running":
		return false
	}
	return true
}

// waitRun acompanha a execução até um estado final, com o prazo de -run-timeout.
func (t *tester) waitRun(id, label string) api.RunDetail {
	start := time.Now()
	deadline := start.Add(t.cfg.runTimeout)
	lastLog := start
	for {
		var d api.RunDetail
		t.get("/api/v1/runs/"+id, &d)
		if terminal(d.Run.Status) {
			info("%s %s terminou em %s com estado %s", label, id, time.Since(start).Round(time.Second), d.Run.Status)
			return d
		}
		if time.Now().After(deadline) {
			fatalf("%s %s não terminou em %s (estado %s, fase %s, %d de %d arquivos)", label, id, t.cfg.runTimeout,
				d.Run.Status, d.Run.Phase, d.Run.FilesProcessed, d.Run.FilesEligible)
		}
		if time.Since(lastLog) >= 30*time.Second {
			lastLog = time.Now()
			info("%s %s: estado %s, fase %s, %d de %d arquivos", label, id, d.Run.Status, d.Run.Phase,
				d.Run.FilesProcessed, d.Run.FilesEligible)
		}
		time.Sleep(3 * time.Second)
	}
}

func describeRun(d api.RunDetail) string {
	var b strings.Builder
	fmt.Fprintf(&b, "estado %s", d.Run.Status)
	if d.Run.Error != "" {
		fmt.Fprintf(&b, ", erro %q", d.Run.Error)
	}
	if sm := d.Run.Summary; sm != nil {
		if sm.Skipped != nil && len(*sm.Skipped) > 0 {
			fmt.Fprintf(&b, ", ignorados %v", *sm.Skipped)
		}
		if sm.Warnings != nil && len(*sm.Warnings) > 0 {
			fmt.Fprintf(&b, ", avisos %q", *sm.Warnings)
		}
	}
	for _, e := range d.Engines {
		fmt.Fprintf(&b, "; %s: disponível=%v autoteste=%v", e.Engine, e.Available, e.SelftestPassed)
		if e.SelftestDetail != "" {
			fmt.Fprintf(&b, " (%s)", e.SelftestDetail)
		}
		if len(e.Skipped) > 0 {
			fmt.Fprintf(&b, " ignorados=%v", e.Skipped)
		}
		if len(e.Errors) > 0 {
			fmt.Fprintf(&b, " erros=%v", e.Errors)
		}
		if e.Error != "" {
			fmt.Fprintf(&b, " erro=%q", e.Error)
		}
	}
	return b.String()
}

func requireCompleted(d api.RunDetail, label string) {
	if d.Run.Status != "completed" {
		fatalf("%s %s não concluiu: %s", label, d.Run.Id, describeRun(d))
	}
}

// checkFilesCoverage confere a cobertura de cada motor e a coerência com o resumo da execução.
func checkFilesCoverage(d api.RunDetail, label string) {
	r, sm := d.Run, d.Run.Summary
	if sm == nil {
		fatalf("%s %s concluída sem resumo", label, r.Id)
	}
	if sm.Status != r.Status || sm.FilesSeen != r.FilesSeen || sm.FilesEligible != r.FilesEligible ||
		sm.BytesEligible != r.BytesEligible {
		fatalf("%s %s: resumo (estado %s, %d vistos, %d elegíveis, %d bytes) diverge da execução (%s, %d, %d, %d)",
			label, r.Id, sm.Status, sm.FilesSeen, sm.FilesEligible, sm.BytesEligible, r.Status, r.FilesSeen,
			r.FilesEligible, r.BytesEligible)
	}
	if sm.FilesEligible <= 0 || sm.FilesEligible > sm.FilesSeen {
		fatalf("%s %s: %d arquivos elegíveis de %d vistos", label, r.Id, sm.FilesEligible, sm.FilesSeen)
	}
	for _, name := range []string{engineYARA, engineClam} {
		var e *api.EngineCoverage
		for i := range d.Engines {
			if d.Engines[i].Engine == name {
				e = &d.Engines[i]
			}
		}
		if e == nil {
			fatalf("%s %s sem cobertura do motor %s", label, r.Id, name)
		}
		if !e.Available || !e.SelftestPassed || e.Error != "" {
			fatalf("%s %s: motor %s disponível=%v autoteste=%v (%s) erro=%q", label, r.Id, name, e.Available,
				e.SelftestPassed, e.SelftestDetail, e.Error)
		}
		// "analyzed" inclui os arquivos resolvidos pelo cache ("from_cache").
		if e.Analyzed <= 0 || e.FromCache > e.Analyzed || e.Analyzed > e.Eligible || e.Eligible > sm.FilesEligible {
			fatalf("%s %s: cobertura incoerente do %s (analisados %d, do cache %d, elegíveis %d; elegíveis na execução %d)",
				label, r.Id, name, e.Analyzed, e.FromCache, e.Eligible, sm.FilesEligible)
		}
		if len(e.Errors) > 0 {
			warn("%s %s: o %s registrou erros por arquivo: %v", label, r.Id, name, e.Errors)
		}
		info("%s %s (regras %s): %d de %d elegíveis analisados (%d pelo cache), %.1f s, autoteste aprovado",
			name, e.Version, e.RulesVersion, e.Analyzed, e.Eligible, e.FromCache, e.Seconds)
	}
}

// runFindings lista os achados vistos na execução, seguindo o cursor.
func (t *tester) runFindings(runID string) []api.Finding {
	var out []api.Finding
	q := url.Values{"run": {runID}, "limit": {"500"}}
	for {
		var page api.FindingPage
		t.get("/api/v1/findings?"+q.Encode(), &page)
		out = append(out, page.Findings...)
		if page.NextBefore == nil || len(page.Findings) == 0 {
			return out
		}
		q.Set("before", strconv.FormatInt(*page.NextBefore, 10))
	}
}

func (t *tester) finding(id int64) api.FindingDetail {
	var d api.FindingDetail
	t.get(fmt.Sprintf("/api/v1/findings/%d", id), &d)
	return d
}

func locPath(l api.Location) string {
	if l.PathHex != nil {
		if b, err := hex.DecodeString(*l.PathHex); err == nil {
			return string(b)
		}
	}
	return l.Path
}

type hit struct {
	id        int64
	engine    string
	signature string
}

func (t *tester) stepFileScan(pos, ben string) scanResult {
	m := loadManifest(pos)
	sr := scanResult{positivos: pos, benigno: ben, ids: map[int64]bool{}}
	body := api.RunCreate{Kind: "files", Paths: &[]string{pos, ben}, Profile: ptrTo(profileName), Incremental: ptrTo(false)}
	run := t.createRun(body, "varredura de arquivos")
	if run.Profile.Name != profileName || run.Incremental {
		fatalf("varredura criada com perfil %s e incremental=%v", run.Profile.Name, run.Incremental)
	}
	ok("varredura de arquivos %s na fila (perfil %s, completa; a mesma Idempotency-Key devolveu a mesma execução)",
		run.Id, run.Profile.Name)
	d := t.waitRun(run.Id, "varredura de arquivos")
	requireCompleted(d, "varredura de arquivos")
	checkFilesCoverage(d, "varredura de arquivos")
	if d.Run.FindingsCount <= 0 || d.Run.Summary.Findings <= 0 {
		fatalf("varredura de arquivos %s sem achados (contagem %d, resumo %d)", run.Id, d.Run.FindingsCount, d.Run.Summary.Findings)
	}
	sr.runID = run.Id

	findings := t.runFindings(run.Id)
	byPath := map[string][]hit{}
	for _, f := range findings {
		sr.ids[f.Id] = true
		det := t.finding(f.Id)
		locs := det.Locations
		if len(locs) == 0 && f.Location != nil {
			locs = []api.Location{*f.Location}
		}
		for _, l := range locs {
			p := locPath(l)
			byPath[p] = append(byPath[p], hit{id: f.Id, engine: f.Engine, signature: f.Signature})
		}
	}

	// Falsos positivos: qualquer achado no corpus benigno ou nos controles negativos.
	negativos := path.Join(pos, "negativos") + "/"
	var fps []string
	for p, hs := range byPath {
		if strings.HasPrefix(p, ben+"/") || strings.HasPrefix(p, negativos) {
			for _, h := range hs {
				fps = append(fps, fmt.Sprintf("%q: %s %s (achado %d)", p, h.engine, h.signature, h.id))
			}
		}
	}
	if len(fps) > 0 {
		sort.Strings(fps)
		fatalf("%d falso(s) positivo(s) na varredura %s:\n  %s", len(fps), run.Id, strings.Join(fps, "\n  "))
	}

	// Detecções esperadas pelo manifesto dos positivos.
	var missing, missingOpt []string
	expected := 0
	for _, e := range m.Entries {
		rel := e.Path
		if e.PathHex != "" {
			if b, err := hex.DecodeString(e.PathHex); err == nil {
				rel = string(b)
			}
		}
		full := path.Join(pos, rel)
		var want []hit
		if e.Expect.ClamAV != "" {
			want = append(want, hit{engine: engineClam, signature: e.Expect.ClamAV})
		}
		for _, rule := range e.Expect.YARA {
			want = append(want, hit{engine: engineYARA, signature: rule})
		}
		for _, w := range want {
			expected++
			var found *hit
			for i, h := range byPath[full] {
				if h.engine == w.engine && h.signature == w.signature {
					found = &byPath[full][i]
				}
			}
			if found == nil {
				msg := fmt.Sprintf("%q sem %s %s", rel, w.engine, w.signature)
				if essentialEntries[e.Path] || !t.cfg.essentialOnly {
					missing = append(missing, msg)
				} else {
					missingOpt = append(missingOpt, msg)
				}
				continue
			}
			switch {
			case e.Path == "eicar/eicar.com" && w.engine == engineClam:
				sr.eicarID = found.id
			case e.Path == "marcador/marcador.txt" && w.signature == sigControl:
				sr.markerID = found.id
			}
		}
	}
	if len(missing) > 0 {
		fatalf("%d detecção(ões) esperada(s) pelo manifesto ausente(s) na varredura %s:\n  %s", len(missing), run.Id,
			strings.Join(missing, "\n  "))
	}
	for _, msg := range missingOpt {
		warn("detecção esperada ausente (não essencial com -essential-only): %s", msg)
	}
	if sr.eicarID == 0 || sr.markerID == 0 {
		fatalf("achados de referência não identificados (EICAR %d, marcador %d)", sr.eicarID, sr.markerID)
	}
	sr.openBefore = t.openTotal()
	ok("varredura de arquivos %s concluída: %d arquivos vistos, %d elegíveis, %d achados distintos; %d de %d detecções "+
		"esperadas pelo manifesto (EICAR pelo ClamAV, marcador pelo YARA-X); nenhum falso positivo em benigno/ nem em "+
		"positivos/negativos/", run.Id, d.Run.FilesSeen, d.Run.FilesEligible, len(findings), expected-len(missingOpt), expected)
	return sr
}

func ptrTo[T any](v T) *T { return &v }

func (t *tester) stepIncremental(sr scanResult) {
	body := api.RunCreate{Kind: "files", Paths: &[]string{sr.positivos, sr.benigno}, Profile: ptrTo(profileName),
		Incremental: ptrTo(true)}
	run := t.createRun(body, "varredura incremental")
	d := t.waitRun(run.Id, "varredura incremental")
	requireCompleted(d, "varredura incremental")
	checkFilesCoverage(d, "varredura incremental")
	findings := t.runFindings(run.Id)
	var extra []string
	for _, f := range findings {
		if !sr.ids[f.Id] {
			extra = append(extra, fmt.Sprintf("achado %d (%s %s)", f.Id, f.Engine, f.Signature))
		}
	}
	if len(extra) > 0 {
		fatalf("a varredura incremental %s criou achados novos para os mesmos arquivos: %s", run.Id, strings.Join(extra, ", "))
	}
	after := t.openTotal()
	if after != sr.openBefore {
		fatalf("achados abertos mudaram com a varredura incremental: %d antes, %d depois", sr.openBefore, after)
	}
	if d.Run.Summary.CacheHits == 0 {
		warn("a varredura incremental %s não aproveitou o cache (cache_hits = 0)", run.Id)
	}
	ok("varredura incremental %s concluída: %d arquivos pelo cache, %d achados revistos sem duplicar; %d achados abertos antes e depois",
		run.Id, d.Run.Summary.CacheHits, len(findings), after)
}

func (t *tester) stepProcesses() {
	pid := t.cfg.memfdPID
	run := t.createRun(api.RunCreate{Kind: "processes"}, "inspeção de processos")
	d := t.waitRun(run.Id, "inspeção de processos")
	requireCompleted(d, "inspeção de processos")

	var inv api.ProcessInventory
	t.get("/api/v1/inventory/processes?run_id="+url.QueryEscape(run.Id), &inv)
	if inv.RunId != run.Id || len(inv.Processes) == 0 {
		fatalf("inventário de processos da inspeção %s vazio ou de outra execução (%s)", run.Id, inv.RunId)
	}
	var systemd, core, executor, sshd, memfd *api.ProcessInfo
	for i := range inv.Processes {
		p := &inv.Processes[i]
		switch {
		case p.Pid == 1 && p.Comm == "systemd":
			systemd = p
		case p.Exe == "/usr/bin/vigiahost" || strings.HasSuffix(p.Exe, "/vigiahost"):
			core = p
		case strings.Contains(p.Exe, "vigiahost-executor"):
			executor = p
		case p.Comm == "sshd":
			sshd = p
		}
		if p.Pid == pid {
			memfd = p
		}
	}
	if systemd == nil {
		fatalf("inventário sem o systemd como PID 1")
	}
	if core == nil && executor == nil {
		fatalf("inventário sem os processos do próprio VigiaHost (core ou executor)")
	}
	if core == nil || executor == nil {
		warn("inventário com core=%v e executor=%v (esperado os dois)", core != nil, executor != nil)
	}
	if sshd == nil {
		warn("sshd não aparece no inventário (normal se o laboratório não roda SSH)")
	}
	if memfd == nil {
		fatalf("o processo de teste memfd (PID %d) não aparece no inventário", pid)
	}
	if memfd.ExeMemfd == nil || !*memfd.ExeMemfd {
		fatalf("o processo de teste PID %d não foi marcado como exe_memfd (exe %q)", pid, memfd.Exe)
	}
	info("inventário: %d processos; systemd PID 1, core=%v, executor=%v, sshd=%v, memfd PID %d com exe %q",
		len(inv.Processes), core != nil, executor != nil, sshd != nil, pid, memfd.Exe)

	var pers api.PersistenceInventory
	t.get("/api/v1/inventory/persistence?run_id="+url.QueryEscape(run.Id), &pers)
	if pers.RunId != run.Id || len(pers.Items) == 0 {
		fatalf("inventário de persistência da inspeção %s vazio ou de outra execução (%s)", run.Id, pers.RunId)
	}
	kinds := map[string]int{}
	for _, it := range pers.Items {
		kinds[it.Kind]++
	}

	var memfdFinding *api.Finding
	findings := t.runFindings(run.Id)
	for i := range findings {
		f := &findings[i]
		if f.Signature == sigMemfd && f.Process != nil && (f.Process.Pid == pid || strings.Contains(f.Process.Exe, memfdName)) {
			memfdFinding = f
		}
	}
	if memfdFinding == nil {
		fatalf("a inspeção %s não acusou %s para o processo de teste PID %d (%d achados na execução)", run.Id, sigMemfd,
			pid, len(findings))
	}
	ok("inspeção de processos %s concluída: %d processos, %d itens de persistência em %d tipos (linha de base=%v); "+
		"execução sem arquivo acusada (%s, severidade %s, achado %d)", run.Id, len(inv.Processes), len(pers.Items),
		len(kinds), pers.Baseline, sigMemfd, memfdFinding.Severity, memfdFinding.Id)
}

func (t *tester) transition(id int64, to, note string) api.FindingDetail {
	var d api.FindingDetail
	t.call(http.MethodPost, fmt.Sprintf("/api/v1/findings/%d/transition", id),
		api.FindingTransition{To: api.FindingState(to), Note: &note}, reqOpts{}, http.StatusOK, &d)
	if string(d.Finding.State) != to {
		fatalf("achado %d: transição para %s resultou em %s", id, to, d.Finding.State)
	}
	if n := len(d.Events); n == 0 || d.Events[n-1].To != to || d.Events[n-1].Actor != t.creds.Username {
		fatalf("achado %d: histórico sem o evento da transição para %s", id, to)
	}
	return d
}

// toNew devolve o achado ao estado "new" pelas transições permitidas (execução anterior interrompida).
func (t *tester) toNew(id int64) {
	note := e2eTag + ": preparação"
	switch st := string(t.finding(id).Finding.State); st {
	case "new":
	case "confirmed":
		t.transition(id, "in_review", note)
		t.transition(id, "new", note)
	case "in_review", "resolved", "false_positive", "excepted":
		t.transition(id, "new", note)
	default:
		fatalf("achado %d em estado desconhecido %q", id, st)
	}
}

func contains(list []api.FindingState, s string) bool {
	for _, v := range list {
		if string(v) == s {
			return true
		}
	}
	return false
}

func (t *tester) stepFindingLifecycle(sr scanResult) {
	// Ciclo de vida no achado do marcador YARA: new → in_review → confirmed, e volta a new no fim.
	id := sr.markerID
	note := e2eTag + ": teste de ponta a ponta"
	t.toNew(id)
	t.transition(id, "in_review", note)
	d := t.transition(id, "confirmed", note)
	if !contains(d.AllowedTransitions, "in_review") || !contains(d.AllowedTransitions, "resolved") ||
		contains(d.AllowedTransitions, "excepted") {
		fatalf("achado %d confirmado com transições permitidas inesperadas: %v", id, d.AllowedTransitions)
	}
	r := t.send(http.MethodPost, fmt.Sprintf("/api/v1/findings/%d/transition", id),
		api.FindingTransition{To: "new", Note: &note}, reqOpts{})
	if r.status != http.StatusConflict {
		fatalf("transição proibida confirmed → new deveria responder 409: %s", r.describe())
	}
	r = t.send(http.MethodPost, fmt.Sprintf("/api/v1/findings/%d/transition", id),
		api.FindingTransition{To: "excepted", Note: &note}, reqOpts{})
	if r.status != http.StatusBadRequest {
		fatalf("transição manual para excepted deveria responder 400: %s", r.describe())
	}
	t.transition(id, "in_review", note)
	t.transition(id, "new", note)
	ok("ciclo do achado %d (marcador YARA): new → in_review → confirmed, transições proibidas recusadas, devolvido a new", id)

	// Exceção por hash no achado do EICAR, com reautenticação.
	id = sr.eicarID
	t.toNew(id)
	f := t.finding(id).Finding
	if f.Sha256 == nil || len(*f.Sha256) != 64 {
		fatalf("achado %d do EICAR sem SHA-256", id)
	}
	reason := e2eTag + ": exceção temporária do teste de ponta a ponta"
	body := api.ExceptionCreate{Scope: "hash", FindingId: &id, Reason: reason}
	if time.Now().After(t.reauthUntil) {
		r := t.send(http.MethodPost, "/api/v1/exceptions", body, reqOpts{})
		if r.status != http.StatusForbidden || r.errCode() != "reauth_required" {
			fatalf("exceção sem reautenticação recente deveria responder 403 reauth_required: %s", r.describe())
		}
		info("exceção sem reautenticação recente recusada (403 reauth_required)")
	} else {
		warn("reautenticação ainda válida; a recusa sem reautenticação não foi conferida nesta execução")
	}
	t.ensureReauth("criar a exceção")
	var exc api.Exception
	t.call(http.MethodPost, "/api/v1/exceptions", body, reqOpts{}, http.StatusCreated, &exc)
	if exc.Scope != "hash" || exc.Sha256 != *f.Sha256 || !exc.Active || exc.CreatedBy != t.creds.Username {
		fatalf("exceção criada com dados inesperados: escopo %s, hash %s, ativa %v, autor %s", exc.Scope, exc.Sha256,
			exc.Active, exc.CreatedBy)
	}
	f = t.finding(id).Finding
	if f.State != "excepted" || f.ExceptionId == nil || *f.ExceptionId != exc.Id {
		fatalf("achado %d deveria estar excepted pela exceção %d (estado %s)", id, exc.Id, f.State)
	}
	t.ensureReauth("revogar a exceção")
	t.call(http.MethodDelete, fmt.Sprintf("/api/v1/exceptions/%d", exc.Id), nil, reqOpts{}, http.StatusNoContent, nil)
	var all, active []api.Exception
	t.get("/api/v1/exceptions?all=true", &all)
	t.get("/api/v1/exceptions", &active)
	var revoked *api.Exception
	for i := range all {
		if all[i].Id == exc.Id {
			revoked = &all[i]
		}
	}
	if revoked == nil || revoked.Active || revoked.RevokedAt == nil || revoked.RevokedBy != t.creds.Username {
		fatalf("exceção %d não aparece revogada na lista completa", exc.Id)
	}
	for _, e := range active {
		if e.Id == exc.Id {
			fatalf("exceção %d revogada continua na lista de exceções ativas", exc.Id)
		}
	}
	t.transition(id, "new", e2eTag+": fim do teste da exceção")
	ok("exceção por hash %d com reautenticação: achado %d do EICAR virou excepted; exceção revogada e achado devolvido a new",
		exc.Id, id)
}

func (t *tester) stepSchedule(ben string) {
	cron, tz := "0 3 * * *", "America/Sao_Paulo"
	var pv api.CronPreview
	t.call(http.MethodPost, "/api/v1/schedules/preview", api.CronPreviewRequest{Cron: cron, Timezone: &tz}, reqOpts{},
		http.StatusOK, &pv)
	if len(pv.Next) != 5 {
		fatalf("prévia do agendamento com %d horários (esperado 5)", len(pv.Next))
	}
	for i, n := range pv.Next {
		u := n.UTC()
		if u.Hour() != 6 || u.Minute() != 0 || (i > 0 && n.Sub(pv.Next[i-1]) != 24*time.Hour) || !n.After(time.Now()) {
			fatalf("prévia do agendamento diário às 03:00 de %s com horário inesperado: %v", tz, pv.Next)
		}
	}
	in := api.ScheduleInput{Name: e2eTag + "-diario-" + randHex(3), Kind: "files", Cron: cron, Timezone: &tz,
		Paths: &[]string{ben}, Enabled: ptrTo(false)}
	var sc api.Schedule
	t.call(http.MethodPost, "/api/v1/schedules", in, reqOpts{}, http.StatusCreated, &sc)
	if sc.Name != in.Name || sc.Enabled || sc.Timezone != tz || sc.CreatedBy != t.creds.Username || len(sc.Upcoming) != 5 ||
		!sc.Upcoming[0].Equal(pv.Next[0]) {
		fatalf("agendamento criado com dados inesperados (ativo=%v, fuso %s, próximas %v)", sc.Enabled, sc.Timezone, sc.Upcoming)
	}
	if !t.hasSchedule(sc.Id) {
		fatalf("agendamento %d não aparece na lista", sc.Id)
	}
	t.call(http.MethodDelete, fmt.Sprintf("/api/v1/schedules/%d", sc.Id), nil, reqOpts{}, http.StatusNoContent, nil)
	if t.hasSchedule(sc.Id) {
		fatalf("agendamento %d continua na lista depois de apagado", sc.Id)
	}
	ok("agendamento diário (%s, %s) criado desativado, próximas 5 execuções às 06:00 UTC iguais à prévia, e apagado",
		cron, tz)
}

func (t *tester) hasSchedule(id int64) bool {
	var list []api.Schedule
	t.get("/api/v1/schedules", &list)
	for _, s := range list {
		if s.Id == id {
			return true
		}
	}
	return false
}

func (t *tester) stepBackup() {
	t.ensureReauth("a cópia do banco")
	r := t.send(http.MethodPost, "/api/v1/backups", nil, reqOpts{})
	if r.status == http.StatusConflict {
		// Já há uma cópia deste segundo: o nome tem resolução de segundos.
		time.Sleep(1200 * time.Millisecond)
		r = t.send(http.MethodPost, "/api/v1/backups", nil, reqOpts{})
	}
	if r.status != http.StatusCreated {
		fatalf("cópia manual do banco: %s", r.describe())
	}
	var bk api.BackupInfo
	r.decode(&bk)
	if bk.Origin != "manual" || len(bk.Sha256) != 64 || bk.Size <= 0 || bk.SchemaVersion < 1 {
		fatalf("cópia manual com dados inesperados: origem %s, %d bytes, esquema %d", bk.Origin, bk.Size, bk.SchemaVersion)
	}
	var list api.BackupList
	t.get("/api/v1/backups", &list)
	var manual, auto *api.BackupInfo
	for i := range list.Backups {
		b := &list.Backups[i]
		if b.Name == bk.Name {
			manual = b
		}
		if b.Origin == "automatic" && auto == nil {
			auto = b
		}
	}
	if manual == nil {
		fatalf("cópia manual %s não aparece em /backups", bk.Name)
	}
	if auto == nil {
		fatalf("nenhuma cópia automática em /backups (o serviço faz uma ao iniciar e uma por dia)")
	}
	ok("cópia manual %s (%d bytes, esquema %d) e cópia automática %s listadas em %s", bk.Name, bk.Size,
		bk.SchemaVersion, auto.Name, list.Directory)
}

func (t *tester) stepAPIToken() {
	t.ensureReauth("criar o token de API")
	name := e2eTag + "-leitura-" + randHex(3)
	var tc api.ApiTokenCreated
	t.call(http.MethodPost, "/api/v1/tokens", api.ApiTokenCreate{Name: name, Role: "reader", ExpiresInDays: 1}, reqOpts{},
		http.StatusCreated, &tc)
	token := tc.Token
	if !strings.HasPrefix(token, "vht_") || tc.Info.Role != "reader" || tc.Info.Name != name {
		fatalf("token de API criado com formato ou perfil inesperado (perfil %s)", tc.Info.Role)
	}
	var ov api.Overview
	t.call(http.MethodGet, "/api/v1/overview", nil, reqOpts{bearer: token}, http.StatusOK, &ov)
	r := t.send(http.MethodPost, "/api/v1/runs", api.RunCreate{Kind: "processes"}, reqOpts{bearer: token})
	if r.status != http.StatusForbidden {
		fatalf("token somente leitura não deveria criar execução: %s", r.describe())
	}
	t.call(http.MethodDelete, fmt.Sprintf("/api/v1/tokens/%d", tc.Info.Id), nil, reqOpts{}, http.StatusNoContent, nil)
	r = t.send(http.MethodGet, "/api/v1/overview", nil, reqOpts{bearer: token})
	if r.status != http.StatusUnauthorized {
		fatalf("token revogado deveria receber 401: %s", r.describe())
	}
	var toks []api.ApiToken
	t.get("/api/v1/tokens", &toks)
	revoked := false
	for _, tk := range toks {
		if tk.Id == tc.Info.Id {
			revoked = tk.RevokedAt != nil
		}
	}
	if !revoked {
		fatalf("token %d não aparece revogado na lista", tc.Info.Id)
	}
	ok("token de API somente leitura %d: leu /overview por Bearer, não criou execução (403), revogado e recusado depois (401)",
		tc.Info.Id)
}

func (t *tester) stepAudit() {
	want := []string{"run_created", "finding_transition", "exception_created", "exception_revoked", "schedule_created",
		"schedule_deleted", "backup_created", "api_token_created", "api_token_revoked"}
	if t.reauths > 0 {
		want = append(want, "reauth")
	}
	seen := map[string]int{}
	total := 0
	q := url.Values{"limit": {"500"}}
	chainChecked := false
	for done := false; !done; {
		var page api.AuditPage
		t.get("/api/v1/audit?"+q.Encode(), &page)
		if !chainChecked {
			if !page.ChainOk {
				at := int64(0)
				if page.BrokenAt != nil {
					at = *page.BrokenAt
				}
				fatalf("cadeia de hashes da auditoria quebrada (registro %d)", at)
			}
			chainChecked = true
		}
		for _, e := range page.Entries {
			if e.Id <= t.auditStart {
				done = true
				break
			}
			total++
			if e.Actor == t.creds.Username {
				seen[e.Action]++
			}
		}
		if page.NextBefore == nil || len(page.Entries) == 0 {
			break
		}
		q.Set("before", strconv.FormatInt(*page.NextBefore, 10))
	}
	var missing []string
	for _, a := range want {
		if seen[a] == 0 {
			missing = append(missing, a)
		}
	}
	if len(missing) > 0 {
		fatalf("auditoria sem as ações do teste: %s", strings.Join(missing, ", "))
	}
	ok("auditoria: cadeia íntegra (chain_ok), %d registros desde o início do teste, com %s", total, strings.Join(want, ", "))
}

func (t *tester) stepLogout() {
	old := t.cookie
	t.logout()
	t.cookie = old
	r := t.send(http.MethodGet, "/api/v1/overview", nil, reqOpts{})
	t.cookie = ""
	if r.status != http.StatusUnauthorized {
		fatalf("sessão encerrada ainda aceita: %s", r.describe())
	}
	ok("logout: sessão encerrada e recusada depois (401)")
}
