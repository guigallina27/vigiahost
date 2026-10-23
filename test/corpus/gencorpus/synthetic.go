//go:build linux

package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/guigallina27/vigiahost/internal/controls"
)

// fileKind descreve um tipo de arquivo da árvore sintética: peso na distribuição, extensão e cabeçalho
// (magic bytes) para que a detecção de tipo pelo conteúdo tenha o que reconhecer.
type fileKind struct {
	name   string
	weight int
	ext    string
	magic  []byte
	text   bool
}

var kinds = []fileKind{
	{name: "php", weight: 35, ext: ".php", magic: []byte("<?php\n"), text: true},
	{name: "js", weight: 15, ext: ".js", text: true},
	{name: "css", weight: 5, ext: ".css", text: true},
	{name: "html", weight: 5, ext: ".html", magic: []byte("<!doctype html>\n"), text: true},
	{name: "json", weight: 3, ext: ".json", magic: []byte("{\n"), text: true},
	{name: "log", weight: 7, ext: ".log", text: true},
	{name: "jpg", weight: 12, ext: ".jpg", magic: []byte{0xFF, 0xD8, 0xFF, 0xE0}},
	{name: "png", weight: 8, ext: ".png", magic: []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}},
	{name: "gif", weight: 2, ext: ".gif", magic: []byte("GIF89a")},
	{name: "svg", weight: 2, ext: ".svg", magic: []byte("<svg xmlns=\"http://www.w3.org/2000/svg\">"), text: true},
	{name: "woff2", weight: 1, ext: ".woff2", magic: []byte("wOF2")},
	{name: "zip", weight: 1, ext: ".zip", magic: []byte{'P', 'K', 0x03, 0x04}},
	{name: "bin", weight: 4, ext: ".bin"},
}

// Tokens de texto plausíveis em código de hospedagem; dão ao conteúdo cara de PHP/JS sem nenhum padrão malicioso.
var tokens = []string{
	"function", "return", "$this->", "array(", "if (", "else", "foreach", "echo", "add_action(", "wp_enqueue_script(",
	"const", "let", "=>", "{", "}", ";", "\n", "  ", "'texto'", "\"valor\"", "null", "true", "false", "=", "+",
	"public", "private", "class", "namespace", "use", "require_once", "__DIR__", "get_option(", "esc_html(", "// comentário",
}

type synthParams struct {
	files    int
	accounts int
	seed     uint64
	plant    int
	median   float64
}

func runSynthetic(args []string) error {
	fs := flag.NewFlagSet("sintetico", flag.ExitOnError)
	out := outFlag(fs)
	p := synthParams{}
	fs.IntVar(&p.files, "files", 1_000_000, "quantidade de arquivos regulares")
	fs.IntVar(&p.accounts, "contas", 0, "contas de hospedagem (padrão: 1 a cada 2.000 arquivos, mínimo 5)")
	fs.Uint64Var(&p.seed, "seed", 1, "semente: a mesma semente gera exatamente a mesma árvore")
	fs.IntVar(&p.plant, "plantar", 20, "controles positivos (marcador YARA) espalhados em pontos sorteados")
	fs.Float64Var(&p.median, "mediana", 1536, "tamanho mediano dos arquivos em bytes (distribuição log-normal)")
	workers := fs.Int("workers", 8, "gravações em paralelo")
	_ = fs.Parse(args)
	if err := prepareOut(*out); err != nil {
		return err
	}
	if p.accounts == 0 {
		p.accounts = max(5, p.files/2000)
	}
	start := time.Now()
	m, err := genSynthetic(*out, p, *workers)
	if err != nil {
		return err
	}
	m.Summary["segundos"] = math.Round(time.Since(start).Seconds()*10) / 10
	return writeManifest(*out, m)
}

// plan é o arquivo a gravar, decidido de forma sequencial (determinística) antes da gravação em paralelo.
type plan struct {
	rel     string
	kind    *fileKind
	size    int
	seed    uint64
	planted bool
}

func genSynthetic(root string, p synthParams, workers int) (Manifest, error) {
	rng := rand.New(rand.NewPCG(p.seed, p.seed^0x9e3779b97f4a7c15))
	totalWeight := 0
	for _, k := range kinds {
		totalWeight += k.weight
	}
	plantAt := map[int]bool{}
	for len(plantAt) < min(p.plant, p.files) {
		plantAt[rng.IntN(p.files)] = true
	}

	plans := make([]plan, p.files)
	dirs := map[string]bool{}
	for i := range plans {
		k := pickKind(rng, totalWeight)
		dir := accountDir(rng, i%p.accounts)
		dirs[dir] = true
		size := int(math.Min(4<<20, math.Max(float64(len(k.magic)+1), p.median*math.Exp(rng.NormFloat64()*1.4))))
		plans[i] = plan{rel: path.Join(dir, fmt.Sprintf("arq%07d%s", i, k.ext)), kind: k, size: size, seed: rng.Uint64(), planted: plantAt[i]}
	}

	dirList := make([]string, 0, len(dirs))
	for d := range dirs {
		dirList = append(dirList, d)
	}
	sort.Strings(dirList)
	for _, d := range dirList {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			return Manifest{}, err
		}
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		bytesSum int64
		byKind   = map[string]int{}
	)
	jobs := make(chan plan, 1024)
	for range max(1, workers) {
		wg.Go(func() {
			buf := new(bytes.Buffer)
			for pl := range jobs {
				data := content(buf, pl)
				err := os.WriteFile(filepath.Join(root, filepath.FromSlash(pl.rel)), data, 0o644)
				mu.Lock()
				if err != nil && firstErr == nil {
					firstErr = err
				}
				bytesSum += int64(len(data))
				byKind[pl.kind.name]++
				mu.Unlock()
			}
		})
	}
	var entries []Entry
	for _, pl := range plans {
		if pl.planted {
			entries = append(entries, Entry{Path: pl.rel, Type: pl.kind.name, Expect: Expect{YARA: []string{controls.YARARuleName}}, Note: "controle positivo plantado"})
		}
		jobs <- pl
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return Manifest{}, firstErr
	}

	special, err := specialEntries(root, plans, rng)
	if err != nil {
		return Manifest{}, err
	}
	entries = append(entries, special...)

	return Manifest{
		Kind:   "sintetico",
		Params: map[string]any{"files": p.files, "contas": p.accounts, "seed": p.seed, "plantar": p.plant, "mediana": p.median},
		Summary: map[string]any{
			"arquivos":   p.files,
			"diretorios": len(dirList),
			"bytes":      bytesSum,
			"por_tipo":   byKind,
			"especiais":  len(special),
			"plantados":  len(plantAt),
		},
		Entries: entries,
	}, nil
}

func pickKind(rng *rand.Rand, total int) *fileKind {
	n := rng.IntN(total)
	for i := range kinds {
		if n < kinds[i].weight {
			return &kinds[i]
		}
		n -= kinds[i].weight
	}
	return &kinds[len(kinds)-1]
}

// accountDir imita a estrutura de hospedagem: home/<conta>/public_html com WordPress, uploads por mês e vendor.
func accountDir(rng *rand.Rand, account int) string {
	base := fmt.Sprintf("home/conta%04d/public_html", account)
	switch rng.IntN(6) {
	case 0:
		return fmt.Sprintf("%s/wp-content/uploads/%d/%02d", base, 2019+rng.IntN(8), 1+rng.IntN(12))
	case 1:
		return fmt.Sprintf("%s/wp-content/plugins/plugin%02d/includes", base, rng.IntN(30))
	case 2:
		return fmt.Sprintf("%s/vendor/pacote%02d/src/Sub%d", base, rng.IntN(40), rng.IntN(5))
	case 3:
		return fmt.Sprintf("%s/wp-includes/js", base)
	case 4:
		return fmt.Sprintf("%s/assets/img", base)
	default:
		return base
	}
}

func content(buf *bytes.Buffer, pl plan) []byte {
	buf.Reset()
	buf.Write(pl.kind.magic)
	r := rand.New(rand.NewPCG(pl.seed, pl.seed>>7))
	if pl.planted {
		buf.WriteString("\n" + controls.Marker + "\n")
	}
	for buf.Len() < pl.size {
		if pl.kind.text {
			buf.WriteString(tokens[r.IntN(len(tokens))])
			buf.WriteByte(' ')
		} else {
			var b [8]byte
			v := r.Uint64()
			for i := range b {
				b[i] = byte(v >> (8 * i))
			}
			buf.Write(b[:])
		}
	}
	// O cabeçalho e o marcador plantado nunca são cortados, mesmo que passem do tamanho sorteado.
	minLen := len(pl.kind.magic)
	if pl.planted {
		minLen += len(controls.Marker) + 2
	}
	return buf.Bytes()[:max(pl.size, minLen)]
}

// specialEntries cria o que o inventário precisa tratar com cuidado: links simbólicos (para dentro, para fora e
// em laço), link físico, FIFO, arquivo sem permissão de leitura e nomes incomuns. Nenhum deles é seguido nem lido
// como conteúdo pelo inventário correto.
func specialEntries(root string, plans []plan, rng *rand.Rand) ([]Entry, error) {
	pick := func() string { return plans[rng.IntN(len(plans))].rel }
	base := "home/conta0000/public_html/especiais"
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(base)), 0o755); err != nil {
		return nil, err
	}
	abs := func(rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }
	var out []Entry
	add := func(rel, typ, note string) {
		e := Entry{Path: rel, Type: typ, Note: note}
		// JSON só representa UTF-8 válido; o nome exato vai em hexadecimal.
		if !utf8.ValidString(rel) {
			e.PathHex = hex.EncodeToString([]byte(rel))
		}
		out = append(out, e)
	}

	type link struct{ rel, target, note string }
	for _, l := range []link{
		{base + "/link-interno", "../" + path.Base(path.Dir(pick())), "link simbólico para diretório da própria conta"},
		{base + "/link-etc", "/etc", "link simbólico para fora do escopo (não deve ser seguido)"},
		{base + "/link-passwd", "/etc/passwd", "link simbólico para arquivo do sistema"},
		{base + "/laco-a", "laco-b", "laço de links simbólicos"},
		{base + "/laco-b", "laco-a", "laço de links simbólicos"},
		{base + "/link-quebrado", "nao-existe", "link simbólico quebrado"},
	} {
		if err := os.Symlink(l.target, abs(l.rel)); err != nil {
			return nil, err
		}
		add(l.rel, "symlink", l.note)
	}

	hard := base + "/link-fisico.php"
	if err := os.Link(abs(pick()), abs(hard)); err != nil {
		return nil, err
	}
	add(hard, "hardlink", "link físico: mesmo inode de outro arquivo (deduplicação por inode)")

	fifo := base + "/fila.fifo"
	if err := syscall.Mkfifo(abs(fifo), 0o644); err != nil {
		return nil, err
	}
	add(fifo, "fifo", "FIFO: abrir para leitura bloquearia; o inventário deve pular")

	locked := base + "/sem-permissao.php"
	if err := os.WriteFile(abs(locked), []byte("<?php echo 1;\n"), 0o000); err != nil {
		return nil, err
	}
	add(locked, "php", "modo 000: ilegível para usuários comuns (o executor, root, lê)")

	for _, name := range []string{"bidi-\u202eetad.php", "quebra\nlinha.php", "controle-\x1b[31m.php", "bytes-invalidos-\xff\xfe.php"} {
		rel := base + "/" + name
		if err := os.WriteFile(abs(rel), []byte("<?php echo 1;\n"), 0o644); err != nil {
			return nil, err
		}
		add(rel, "php", "nome com caracteres de controle, bidi ou bytes inválidos")
	}
	return out, nil
}
