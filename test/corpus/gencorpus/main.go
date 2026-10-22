// Comando gencorpus gera o corpus de testes do VigiaHost (escopo, seção 20) em um diretório do laboratório:
//
//	gencorpus positivos -out DIR            controles positivos inofensivos (EICAR, marcador YARA) e negativos
//	gencorpus sintetico -out DIR -files N   árvore sintética de hospedagem com N arquivos, determinística pela semente
//	gencorpus benigno   -out DIR            CMS e frameworks oficiais (benign.json), conferidos pelo SHA-256
//	gencorpus regra     -out ARQUIVO        regra YARA do controle positivo
//	gencorpus verificar -dir DIR            confere um corpus contra o manifesto com o ClamAV e o YARA-X reais
//	gencorpus sobreposicao -dir DIR         compara o LMD instalado com o ClamAV (oficial e só com as assinaturas rfxn)
//
// Cada comando grava manifest.json com o que foi gerado e o que cada motor deve (ou não) detectar.
// Nunca há malware real: o corpus inteiro é gerado ou baixado de fontes oficiais na hora do teste.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "positivos":
		err = runPositive(args)
	case "sintetico":
		err = runSynthetic(args)
	case "benigno":
		err = runBenign(args)
	case "regra":
		err = runRule(args)
	case "verificar":
		err = runVerify(args)
	case "sobreposicao":
		err = runOverlap(args)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gencorpus:", err)
		os.Exit(1)
	}
}

var errNoOut = errors.New("informe -out")

func usage() {
	fmt.Fprintln(os.Stderr, "uso: gencorpus positivos|sintetico|benigno|regra -out DESTINO [opções] | verificar|sobreposicao -dir CORPUS")
}

// Expect diz o que cada motor deve reportar para o arquivo; vazio significa "nada".
type Expect struct {
	ClamAV string   `json:"clamav,omitempty"`
	YARA   []string `json:"yara,omitempty"`
	// Heuristic marca arquivos inertes com padrão típico de ofuscação, que regras heurísticas podem acusar.
	Heuristic bool `json:"heuristic,omitempty"`
}

// Entry descreve um arquivo do corpus. Path é relativo ao diretório do manifesto.
type Entry struct {
	Path string `json:"path"`
	// PathHex traz o nome exato em hexadecimal quando ele não é UTF-8 válido.
	PathHex string `json:"path_hex,omitempty"`
	Type    string `json:"type"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256,omitempty"`
	Expect  Expect `json:"expect"`
	Note    string `json:"note,omitempty"`
}

// Manifest é gravado em manifest.json na raiz de cada corpus gerado.
type Manifest struct {
	Kind    string         `json:"kind"`
	Version int            `json:"version"`
	Params  map[string]any `json:"params,omitempty"`
	Summary map[string]any `json:"summary,omitempty"`
	Entries []Entry        `json:"entries"`
}

func writeManifest(dir string, m Manifest) error {
	m.Version = 1
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), append(b, '\n'), 0o644)
}

// prepareOut exige um destino vazio ou inexistente, para nunca misturar corpus com outros arquivos.
func prepareOut(dir string) error {
	if dir == "" {
		return fmt.Errorf("informe -out")
	}
	entries, err := os.ReadDir(dir)
	if err == nil && len(entries) > 0 {
		return fmt.Errorf("%s não está vazio", dir)
	}
	return os.MkdirAll(dir, 0o755)
}

func outFlag(fs *flag.FlagSet) *string {
	return fs.String("out", "", "diretório de destino (vazio ou inexistente)")
}
