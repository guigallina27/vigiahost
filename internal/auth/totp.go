package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) usa HMAC-SHA1, padrão dos aplicativos autenticadores
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	"rsc.io/qr"
)

const (
	totpPeriod = 30
	totpDigits = 6
	// Issuer aparece no aplicativo autenticador.
	Issuer = "VigiaHost"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret gera 160 bits aleatórios em base32.
func NewTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return b32.EncodeToString(b)
}

func hotp(key []byte, counter int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter)) //nolint:gosec // passo de tempo, sempre positivo
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// TOTPCode calcula o código do passo (usado nos testes e na verificação).
func TOTPCode(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	return hotp(key, step), nil
}

// Step é o passo de 30 s do instante.
func Step(t time.Time) int64 { return t.Unix() / totpPeriod }

// VerifyTOTP aceita o código do passo atual e de um passo antes ou depois (relógios desalinhados) e devolve o passo
// que casou, para o chamador impedir reuso (o passo precisa ser maior que o último aceito).
func VerifyTOTP(secret, code string, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}
	cur := Step(now)
	for _, s := range []int64{cur, cur - 1, cur + 1} {
		if hmac.Equal([]byte(hotp(key, s)), []byte(code)) {
			return s, true
		}
	}
	return 0, false
}

// TOTPURI monta o endereço otpauth:// que os aplicativos leem pelo QR.
func TOTPURI(secret, username string) string {
	label := url.PathEscape(Issuer + ":" + username)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", Issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(totpDigits))
	v.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// QRMatrix devolve o QR como linhas de "0" e "1"; a interface desenha em SVG (a CSP não permite imagem data:).
func QRMatrix(text string) ([]string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return nil, err
	}
	rows := make([]string, c.Size)
	var b strings.Builder
	for y := 0; y < c.Size; y++ {
		b.Reset()
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
		rows[y] = b.String()
	}
	return rows, nil
}

// NewRecoveryCodes gera 10 códigos de uso único (formato xxxxx-xxxxx, alfabeto sem caracteres ambíguos).
func NewRecoveryCodes() []string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	out := make([]string, 10)
	for i := range out {
		b := make([]byte, 10)
		_, _ = rand.Read(b)
		var s strings.Builder
		for j, c := range b {
			if j == 5 {
				s.WriteByte('-')
			}
			s.WriteByte(alphabet[int(c)%len(alphabet)])
		}
		out[i] = s.String()
	}
	return out
}

// NormalizeRecoveryCode aceita o código com ou sem hífen, maiúsculas ou espaços.
func NormalizeRecoveryCode(c string) string {
	c = strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(c)))
	if len(c) != 10 {
		return ""
	}
	return c[:5] + "-" + c[5:]
}
