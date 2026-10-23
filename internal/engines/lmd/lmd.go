// Package lmd é o adaptador do Linux Malware Detect (LMD/maldet) 2.x como fonte adicional de assinaturas
// (ADR-023). O VigiaHost não instala, não atualiza e não reconfigura o LMD: lê a instalação feita pelo
// administrador, roda só os estágios nativos (hash, hex, csig e YARA) sobre os arquivos que o inventário já abriu e
// nunca deixa o LMD mover, limpar ou apagar nada.
//
// Os arquivos chegam ao maldet como /proc/<pid>/fd/<n> do processo da varredura (ADR-018): nenhum nome de arquivo
// da conta vira argumento, linha de lista ou campo de relatório, e o resultado volta ligado ao descritor.
package lmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/guigallina27/vigiahost/internal/fsperm"
)

// Dir é o diretório de instalação do LMD (relativo à raiz), o mesmo do install.sh oficial.
const Dir = "usr/local/maldetect"

// MinMajor é a versão principal mínima suportada: a 2.0 trouxe o relatório JSON, a variável LMD_BASEDIR e removeu
// o Perl; a 1.6 grava sessões e temporários só dentro da própria instalação.
const MinMajor = 2

// Install descreve a instalação encontrada.
type Install struct {
	Dir        string `json:"dir"`
	Version    string `json:"version"`
	SigVersion string `json:"sig_version,omitempty"`
	// SigDate é a data do conjunto de assinaturas (AAAA-MM-DD), tirada da versão (AAAAMMDD...) ou do arquivo.
	SigDate    string `json:"sig_date,omitempty"`
	Signatures Counts `json:"signatures"`
	// ClamAVLinked lista assinaturas do LMD (rfxn.*) encontradas nos diretórios do ClamAV: o clamd já as carrega.
	ClamAVLinked []string `json:"clamav_linked,omitempty"`
}

// Counts são as quantidades de assinaturas por tipo, como o LMD as carrega.
type Counts struct {
	MD5    int `json:"md5"`
	SHA256 int `json:"sha256"`
	HEX    int `json:"hex"`
	CSIG   int `json:"csig"`
	YARA   int `json:"yara"`
	User   int `json:"user"`
}

// Total soma todas as assinaturas.
func (c Counts) Total() int { return c.MD5 + c.SHA256 + c.HEX + c.CSIG + c.YARA + c.User }

// Erros de descoberta, com orientação para o operador.
var (
	ErrNotInstalled = errors.New("LMD (maldet) não instalado em /usr/local/maldetect")
	ErrUnsupported  = errors.New("versão do LMD não suportada")
)

var versionLine = regexp.MustCompile(`(?m)^lmd_version="?([0-9]+(?:\.[0-9]+){1,3})"?\s*$`)

// Diretórios de assinaturas do ClamAV onde o install.sh e a atualização do LMD copiam as assinaturas rfxn.*.
var clamavDirs = []string{"usr/local/cpanel/3rdparty/share/clamav", "var/lib/clamav", "var/clamav", "usr/share/clamav", "usr/local/share/clamav"}

// Discover lê a instalação sem executá-la: versão pelo script, assinaturas pelos arquivos. root é a raiz do sistema
// (os.DirFS("/")). Devolve a instalação e um erro que explica por que ela não pode ser usada (não instalado,
// versão antiga, permissões inseguras); a instalação volta preenchida mesmo com erro, para a tela mostrar o que há.
func Discover(root fs.FS) (Install, error) {
	in := Install{Dir: "/" + Dir}
	script, err := fs.ReadFile(root, Dir+"/maldet")
	if err != nil {
		return in, ErrNotInstalled
	}
	if _, err := fs.Stat(root, Dir+"/internals/internals.conf"); err != nil {
		return in, fmt.Errorf("%w: internals/internals.conf ausente", ErrNotInstalled)
	}
	m := versionLine.FindSubmatch(script)
	if m == nil {
		return in, errors.New("versão do LMD não identificada no script maldet")
	}
	in.Version = string(m[1])
	in.SigVersion = strings.TrimSpace(firstLine(root, Dir+"/sigs/maldet.sigs.ver"))
	in.SigDate = sigDate(root, in.SigVersion)
	in.Signatures = countSignatures(root)
	for _, d := range clamavDirs {
		for _, n := range []string{"rfxn.hdb", "rfxn.hsb", "rfxn.ndb", "rfxn.yara"} {
			if info, err := fs.Stat(root, d+"/"+n); err == nil && info.Mode().IsRegular() {
				in.ClamAVLinked = append(in.ClamAVLinked, "/"+d+"/"+n)
			}
		}
	}
	if major(in.Version) < MinMajor {
		return in, fmt.Errorf("%w: %s (mínimo %d.0)", ErrUnsupported, in.Version, MinMajor)
	}
	// O maldet roda como root dentro da execução: o script e as bibliotecas precisam ser do root e não graváveis
	// por outros usuários, senão qualquer conta poderia trocar o código executado.
	for _, p := range []string{Dir, Dir + "/maldet", Dir + "/internals", Dir + "/internals/internals.conf", Dir + "/internals/lmd.lib.sh"} {
		info, err := fs.Stat(root, p)
		if err != nil {
			return in, fmt.Errorf("instalação do LMD incompleta: /%s: %w", p, err)
		}
		if !trusted(info) {
			return in, fmt.Errorf("instalação do LMD insegura: /%s precisa ser do root e sem escrita para outros usuários", p)
		}
	}
	return in, nil
}

// trusted confere dono e permissões (trocado nos testes, que não rodam como root).
var trusted = fsperm.RootOnly

func major(v string) int {
	n, _ := strconv.Atoi(strings.SplitN(v, ".", 2)[0])
	return n
}

func firstLine(root fs.FS, p string) string {
	f, err := root.Open(p)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	if sc.Scan() {
		line := sc.Text()
		if len(line) > 64 {
			line = line[:64]
		}
		return line
	}
	return ""
}

// sigDate tira a data da versão das assinaturas (o rfxn usa AAAAMMDD seguido de um serial); sem isso, usa a data do
// arquivo de versão.
func sigDate(root fs.FS, ver string) string {
	if len(ver) >= 8 {
		if t, err := time.Parse("20060102", ver[:8]); err == nil && t.Year() >= 2000 {
			return t.Format(time.DateOnly)
		}
	}
	if info, err := fs.Stat(root, Dir+"/sigs/maldet.sigs.ver"); err == nil {
		return info.ModTime().UTC().Format(time.DateOnly)
	}
	return ""
}

var yaraRule = regexp.MustCompile(`(?m)^\s*(?:(?:private|global)\s+)*rule\s+[A-Za-z_]`)

func countSignatures(root fs.FS) Counts {
	sig := Dir + "/sigs/"
	c := Counts{
		MD5:    countLines(root, sig+"md5v2.dat"),
		SHA256: countLines(root, sig+"sha256v2.dat"),
		HEX:    countLines(root, sig+"hex.dat"),
		CSIG:   countLines(root, sig+"csig.dat"),
		YARA:   countYARA(root, sig+"rfxn.yara"),
	}
	c.User = countLines(root, sig+"custom.md5.dat") + countLines(root, sig+"custom.hex.dat") +
		countLines(root, sig+"custom.sha256.dat") + countLines(root, sig+"custom.csig.dat") +
		countYARA(root, sig+"custom.yara")
	if ents, err := fs.ReadDir(root, sig+"custom.yara.d"); err == nil {
		for _, e := range ents {
			if e.Type().IsRegular() && (strings.HasSuffix(e.Name(), ".yar") || strings.HasSuffix(e.Name(), ".yara")) {
				c.User += countYARA(root, sig+"custom.yara.d/"+e.Name())
			}
		}
	}
	return c
}

func countLines(root fs.FS, p string) int {
	f, err := root.Open(p)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) > 0 && line[0] != '#' {
			n++
		}
	}
	return n
}

func countYARA(root fs.FS, p string) int {
	data, err := fs.ReadFile(root, p)
	if err != nil {
		return 0
	}
	return len(yaraRule.FindAll(data, -1))
}

// --- relatório ---

// Hit é uma detecção do LMD ligada a um arquivo da lista.
type Hit struct {
	Signature string `json:"signature"`
	// Type é o estágio que detectou: MD5, SHA256, HEX, CSIG, YARA (como o LMD informa).
	Type string `json:"type"`
	// Hash é o hash calculado pelo LMD (SHA-256 ou MD5, conforme o modo).
	Hash string `json:"hash,omitempty"`
	// File é o caminho como o LMD o citou (sempre /proc/<pid>/fd/<n> no uso do produto).
	File        string `json:"file"`
	Quarantined bool   `json:"quarantined,omitempty"`
}

// Report é o resultado de uma sessão de varredura do maldet.
type Report struct {
	ScanID           string
	Version          string
	SigVersion       string
	HashType         string
	TotalFiles       int
	TotalHits        int
	TotalQuarantined int
	QuarantineOn     bool
	Hits             []Hit
}

// ParseJSONReport interpreta a saída de "maldet --json-report SCANID" (esquema 1.x da 2.0). Campos desconhecidos
// são ignorados; versão principal do esquema diferente de 1 é recusada (o chamador cai para o TSV da sessão).
func ParseJSONReport(data []byte, scanID string) (Report, error) {
	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Scanner       struct {
			Version    string `json:"version"`
			HashType   string `json:"hash_type"`
			SigVersion string `json:"sig_version"`
		} `json:"scanner"`
		Reports []struct {
			ScanID            string `json:"scan_id"`
			TotalFiles        int    `json:"total_files"`
			TotalHits         int    `json:"total_hits"`
			TotalQuarantined  int    `json:"total_quarantined"`
			QuarantineEnabled bool   `json:"quarantine_enabled"`
			Hits              []struct {
				Signature   string `json:"signature"`
				File        string `json:"file"`
				HitType     string `json:"hit_type"`
				Quarantined bool   `json:"quarantined"`
				Hash        string `json:"hash"`
			} `json:"hits"`
		} `json:"reports"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return Report{}, fmt.Errorf("relatório JSON do LMD ilegível: %w", err)
	}
	if !strings.HasPrefix(doc.SchemaVersion, "1.") {
		return Report{}, fmt.Errorf("esquema do relatório JSON do LMD não suportado: %q", doc.SchemaVersion)
	}
	for _, r := range doc.Reports {
		if r.ScanID != scanID {
			continue
		}
		rep := Report{ScanID: r.ScanID, Version: doc.Scanner.Version, SigVersion: doc.Scanner.SigVersion,
			HashType: doc.Scanner.HashType, TotalFiles: r.TotalFiles, TotalHits: r.TotalHits,
			TotalQuarantined: r.TotalQuarantined, QuarantineOn: r.QuarantineEnabled}
		for _, h := range r.Hits {
			rep.Hits = append(rep.Hits, Hit{Signature: clip(h.Signature, 256), Type: clip(h.HitType, 16),
				Hash: clip(h.Hash, 128), File: clip(h.File, 4096), Quarantined: h.Quarantined})
		}
		return rep, nil
	}
	return Report{}, fmt.Errorf("relatório JSON do LMD sem a sessão %s", scanID)
}

// ParseSessionTSV interpreta o arquivo de sessão session.tsv.SCANID da 2.0 (cabeçalho "#LMD:v1" e uma linha por
// detecção, separada por tabulação: assinatura, arquivo, destino da quarentena, tipo, rótulo, hash, tamanho, dono,
// grupo, modo, mtime). É o caminho de reserva quando o JSON falha.
func ParseSessionTSV(data []byte, scanID string) (Report, error) {
	rep := Report{ScanID: scanID}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	header := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#LMD:") {
			f := strings.Split(line, "\t")
			if len(f) < 3 || f[0] != "#LMD:v1" || f[1] != "scan" || f[2] != scanID {
				return Report{}, fmt.Errorf("sessão do LMD com cabeçalho inesperado: %q", clip(line, 80))
			}
			header = true
			if len(f) >= 16 {
				rep.TotalFiles, _ = strconv.Atoi(f[10])
				rep.TotalHits, _ = strconv.Atoi(f[11])
				rep.Version, rep.SigVersion, rep.HashType = f[13], f[14], f[15]
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 6 {
			continue
		}
		h := Hit{Signature: clip(f[0], 256), File: clip(f[1], 4096), Type: clip(f[3], 16), Hash: clip(f[5], 128)}
		h.Quarantined = f[2] != "" && f[2] != "-"
		if h.Quarantined {
			rep.TotalQuarantined++
		}
		rep.Hits = append(rep.Hits, h)
	}
	if err := sc.Err(); err != nil {
		return Report{}, err
	}
	if !header {
		return Report{}, errors.New("sessão do LMD sem cabeçalho #LMD:v1")
	}
	return rep, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ScanIDPattern é o formato do identificador de sessão (AAMMDD-HHMM.PID).
var ScanIDPattern = regexp.MustCompile(`^[0-9]{6}-[0-9]{4}\.[0-9]{1,10}$`)

var reportLine = regexp.MustCompile(`--report ([0-9]{6}-[0-9]{4}\.[0-9]{1,10})`)

// ScanIDFromOutput acha o identificador da sessão na saída do maldet ("to view run: maldet --report ID").
func ScanIDFromOutput(out []byte) string {
	ms := reportLine.FindAllSubmatch(out, -1)
	if len(ms) == 0 {
		return ""
	}
	return string(ms[len(ms)-1][1])
}

// FDIndex mapeia /proc/<pid>/fd/<n> de volta para o índice do lote; caminhos de outro processo ou fora do lote não
// valem (o relatório é tratado como entrada não confiável).
func FDIndex(path string, pid int, fds map[int]int) (int, bool) {
	rest, ok := strings.CutPrefix(path, "/proc/"+strconv.Itoa(pid)+"/fd/")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil || strconv.Itoa(n) != rest {
		return 0, false
	}
	i, ok := fds[n]
	return i, ok
}
