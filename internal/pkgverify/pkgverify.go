// Package pkgverify confere arquivos do sistema contra o banco do gerenciador de pacotes (RPM ou dpkg): a que pacote
// cada arquivo pertence, se o conteúdo e os metadados conferem com o pacote instalado e se o pacote ou o repositório
// de origem tem assinatura conferível (escopo, seções 7.5 e 10).
//
// É a base reutilizável da verificação de integridade (execução "integrity"), do inspetor de processos (executável
// de pacote alterado) e da triagem do AIDE e do Chkrootkit: "este arquivo pertence a qual pacote, e a versão
// instalada confere com o pacote assinado?".
//
// Somente leitura. Os comandos rodam com caminhos fixos (/usr/bin/rpm, /usr/bin/dpkg...), argumentos montados aqui
// e ambiente mínimo; os arquivos de banco do dpkg são lidos diretamente. Os interpretadores aceitam a saída real
// das ferramentas (fixtures em testdata, capturadas no laboratório).
package pkgverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Manager identifica o gerenciador de pacotes do sistema.
type Manager string

const (
	ManagerNone Manager = ""
	RPM         Manager = "rpm"
	DPKG        Manager = "dpkg"
)

// Caminhos fixos das ferramentas (nunca procurados no PATH).
const (
	rpmBin       = "/usr/bin/rpm"
	dpkgBin      = "/usr/bin/dpkg"
	dpkgQueryBin = "/usr/bin/dpkg-query"
	debsumsBin   = "/usr/bin/debsums"
)

// ErrNoManager indica sistema sem RPM nem dpkg utilizável.
var ErrNoManager = errors.New("nenhum gerenciador de pacotes reconhecido (rpm ou dpkg)")

// Package identifica um pacote instalado.
type Package struct {
	Name string `json:"name"`
	// Version: no RPM, [época:]versão-lançamento (a época só aparece quando não é zero); no dpkg, a versão Debian.
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
}

// String devolve "nome-versão.arquitetura" (forma do RPM) ou "nome versão" quando falta a arquitetura.
func (p Package) String() string {
	if p.Name == "" {
		return ""
	}
	s := p.Name
	if p.Version != "" {
		s += "-" + p.Version
	}
	if p.Arch != "" {
		s += "." + p.Arch
	}
	return s
}

// Runner executa uma ferramenta e escreve a saída padrão em stdout. Devolve o texto do erro padrão (truncado), o
// código de saída e erro só quando o processo nem rodou ou o contexto acabou. Os testes trocam por um falso.
type Runner interface {
	Run(ctx context.Context, stdout io.Writer, name string, args ...string) (stderr string, code int, err error)
}

// ExecRunner roda o comando de verdade, com locale C (saída estável para os interpretadores) e PATH mínimo.
type ExecRunner struct{}

// maxStderr limita o erro padrão guardado por comando (o debsums -s relata os arquivos por ele).
const maxStderr = 1 << 20

// Run implementa Runner.
func (ExecRunner) Run(ctx context.Context, stdout io.Writer, name string, args ...string) (string, int, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // ferramenta de caminho fixo e argumentos montados neste pacote
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdout = stdout
	var errb limitedBuffer
	errb.max = maxStderr
	cmd.Stderr = &errb
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return errb.String(), -1, ctx.Err()
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return errb.String(), ee.ExitCode(), nil
	}
	if err != nil {
		return errb.String(), -1, err
	}
	return errb.String(), 0, nil
}

// limitedBuffer guarda até max bytes e descarta o resto sem falhar a escrita.
type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string { return b.buf.String() }

// cappedWriter é um buffer com teto: passar do teto vira erro, e o comando é interrompido pelo pipe fechado.
type cappedWriter struct {
	buf bytes.Buffer
	max int
}

var errOutputTooLarge = errors.New("saída da ferramenta acima do limite")

func (w *cappedWriter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.max {
		return 0, errOutputTooLarge
	}
	return w.buf.Write(p)
}

// RunOutput executa a ferramenta e devolve a saída inteira (até max bytes), o erro padrão e o código de saída.
func RunOutput(ctx context.Context, r Runner, max int, name string, args ...string) ([]byte, string, int, error) {
	return run(ctx, r, max, name, args...)
}

// run executa e devolve a saída inteira (até max bytes).
func run(ctx context.Context, r Runner, max int, name string, args ...string) ([]byte, string, int, error) {
	w := &cappedWriter{max: max}
	stderr, code, err := r.Run(ctx, w, name, args...)
	return w.buf.Bytes(), stderr, code, err
}

// Detect descobre o gerenciador pela presença da ferramenta e do banco. Em sistemas Debian com rpm instalado (alien),
// vale o dpkg.
func Detect(root string) Manager {
	exists := func(p string) bool {
		_, err := os.Stat(filepath.Join(root, p))
		return err == nil
	}
	dpkg := exists(dpkgQueryBin) && exists("var/lib/dpkg/status")
	rpm := exists(rpmBin) && (exists("var/lib/rpm") || exists("usr/lib/sysimage/rpm"))
	switch {
	case dpkg && (exists("etc/debian_version") || !rpm):
		return DPKG
	case rpm:
		return RPM
	}
	return ManagerNone
}

// Verifier responde às perguntas sobre pacotes com cache em memória: dono de cada arquivo, resumos esperados por
// pacote e assinaturas. Seguro para uso concorrente.
type Verifier struct {
	Manager Manager
	Runner  Runner
	// Root é a raiz onde o banco do dpkg é lido (padrão "/"); os comandos sempre consultam o sistema em execução.
	Root string

	mu       sync.Mutex
	owners   map[string][]Package // caminho → donos (vazio = nenhum pacote)
	digests  map[string]map[string]fileDigest
	dpkgPkgs map[string]Package // "nome:arquitetura" e "nome" → pacote (status do dpkg)
	// conffiles: "nome:arquitetura" → caminho → md5 da configuração registrado na instalação (dpkg).
	conffiles map[string]map[string]string
	sigs      *SignatureReport
}

// New devolve um verificador para o sistema em execução.
func New() *Verifier {
	return &Verifier{Manager: Detect("/"), Runner: ExecRunner{}, Root: "/"}
}

func (v *Verifier) root() string {
	if v.Root == "" {
		return "/"
	}
	return v.Root
}

// onDisk devolve onde o arquivo do sistema está a partir da raiz configurada.
func (v *Verifier) onDisk(p string) string {
	if v.root() == "/" {
		return p
	}
	return filepath.Join(v.root(), filepath.FromSlash(p))
}

func (v *Verifier) runner() Runner {
	if v.Runner == nil {
		return ExecRunner{}
	}
	return v.Runner
}

// Available informa se há gerenciador reconhecido.
func (v *Verifier) Available() bool { return v.Manager == RPM || v.Manager == DPKG }

func (v *Verifier) check() error {
	if !v.Available() {
		return ErrNoManager
	}
	return nil
}

// usrMergeAlternates devolve formas equivalentes do caminho em sistemas com /usr unificado (/bin → /usr/bin): o
// banco do dpkg do Debian 12 registra /bin/ls, enquanto o processo mostra /usr/bin/ls.
func usrMergeAlternates(p string) []string {
	out := []string{p}
	if rest, ok := strings.CutPrefix(p, "/usr"); ok && strings.HasPrefix(rest, "/") {
		out = append(out, rest)
	} else {
		for _, d := range []string{"/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/"} {
			if strings.HasPrefix(p, d) {
				out = append(out, "/usr"+p)
				break
			}
		}
	}
	return out
}

func describeExit(name string, code int, stderr string) error {
	msg := strings.TrimSpace(stderr)
	if i := strings.IndexByte(msg, '\n'); i > 0 {
		msg = msg[:i]
	}
	if msg == "" {
		return fmt.Errorf("%s terminou com código %d", filepath.Base(name), code)
	}
	return fmt.Errorf("%s terminou com código %d: %s", filepath.Base(name), code, msg)
}
