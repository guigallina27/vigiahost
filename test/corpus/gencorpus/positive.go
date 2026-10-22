package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"strings"

	"github.com/guigallina27/vigiahost/internal/controls"
)

// positiveFile é um item do corpus de controles; Sparse cria arquivo grande sem ocupar disco.
type positiveFile struct {
	path   string
	typ    string
	data   []byte
	sparse int64 // tamanho total; o conteúdo vai no fim do arquivo
	expect Expect
	note   string
}

func runPositive(args []string) error {
	fs := flag.NewFlagSet("positivos", flag.ExitOnError)
	out := outFlag(fs)
	large := fs.Int64("grande", 512<<20, "tamanho do arquivo esparso com o marcador no fim (fila de arquivos grandes)")
	_ = fs.Parse(args)
	if err := prepareOut(*out); err != nil {
		return err
	}
	files, err := positiveFiles(*large)
	if err != nil {
		return err
	}
	m := Manifest{Kind: "positivos", Params: map[string]any{"grande": *large}}
	for _, f := range files {
		e, err := writePositive(*out, f)
		if err != nil {
			return err
		}
		m.Entries = append(m.Entries, e)
	}
	return writeManifest(*out, m)
}

func positiveFiles(large int64) ([]positiveFile, error) {
	eicar := controls.EICAR()
	marker := controls.MarkerFile()
	yaraHit := Expect{YARA: []string{controls.YARARuleName}}
	clamHit := Expect{ClamAV: controls.ClamAVEICARName}

	zipped, err := zipOf("eicar.com", eicar)
	if err != nil {
		return nil, err
	}
	nested, err := zipOf("interno.zip", zipped)
	if err != nil {
		return nil, err
	}

	// PHP com o marcador em comentário: o padrão de webshell real é código; aqui só há um echo.
	php := []byte("<?php\n// " + controls.Marker + "\necho 'VigiaHost: controle positivo inerte';\n")
	// Conteúdo PHP com cabeçalho JPEG: testa o roteamento pelo tipo real, e não pela extensão.
	fakeJPEG := append([]byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00}, php...)
	// Padrão de ofuscação comum em webshells, com conteúdo decodificado inofensivo:
	// base64 de "echo 'VigiaHost: controle inerte';".
	obfuscated := []byte("<?php eval(base64_decode('ZWNobyAnVmlnaWFIb3N0OiBjb250cm9sZSBpbmVydGUnOw=='));\n")

	deep := "marcador/profundo/" + strings.Repeat("nivel/", 40) + "marcador.txt"

	return []positiveFile{
		{path: "eicar/eicar.com", typ: "eicar", data: eicar, expect: clamHit, note: "arquivo de teste EICAR padrão"},
		{path: "eicar/eicar.zip", typ: "zip", data: zipped, expect: clamHit, note: "EICAR dentro de ZIP"},
		{path: "eicar/aninhado.zip", typ: "zip", data: nested, expect: clamHit, note: "EICAR em ZIP dentro de ZIP"},
		{path: "marcador/marcador.txt", typ: "text", data: marker, expect: yaraHit},
		{path: "marcador/shell.php", typ: "php", data: php, expect: yaraHit},
		{path: "marcador/imagem.jpg", typ: "php", data: fakeJPEG, expect: yaraHit, note: "PHP disfarçado de JPEG"},
		{path: "marcador/nomes/foto\u202egpj.php", typ: "php", data: php, expect: yaraHit, note: "nome com inversão bidi (U+202E)"},
		{path: "marcador/nomes/quebra\nde-linha.php", typ: "php", data: php, expect: yaraHit, note: "nome com quebra de linha"},
		{path: "marcador/nomes/ espaço e acentuação .php", typ: "php", data: php, expect: yaraHit, note: "espaços e acentos no nome"},
		{path: deep, typ: "text", data: marker, expect: yaraHit, note: "41 níveis de diretório"},
		{path: "marcador/grande.bin", typ: "binary", data: marker, sparse: large, expect: yaraHit, note: "arquivo esparso grande com o marcador no fim"},
		{path: "heuristica/ofuscado.php", typ: "php", data: obfuscated, expect: Expect{Heuristic: true}, note: "eval(base64_decode()) com conteúdo inofensivo"},
		{path: "negativos/limpo.txt", typ: "text", data: controls.NegativeFile(), note: "controle negativo"},
		{path: "negativos/limpo.php", typ: "php", data: []byte("<?php\necho 'ola';\n"), note: "controle negativo"},
	}, nil
}

func writePositive(root string, f positiveFile) (Entry, error) {
	full := filepath.Join(root, filepath.FromSlash(f.path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return Entry{}, err
	}
	if f.sparse == 0 {
		if err := os.WriteFile(full, f.data, 0o644); err != nil {
			return Entry{}, err
		}
		sum := sha256.Sum256(f.data)
		return Entry{Path: f.path, Type: f.typ, Size: int64(len(f.data)), SHA256: hex.EncodeToString(sum[:]), Expect: f.expect, Note: f.note}, nil
	}
	fh, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return Entry{}, err
	}
	defer func() { _ = fh.Close() }()
	if err := fh.Truncate(f.sparse); err != nil {
		return Entry{}, err
	}
	if _, err := fh.WriteAt(f.data, f.sparse-int64(len(f.data))); err != nil {
		return Entry{}, err
	}
	return Entry{Path: f.path, Type: f.typ, Size: f.sparse, Expect: f.expect, Note: f.note}, fh.Close()
}

func zipOf(name string, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func runRule(args []string) error {
	fs := flag.NewFlagSet("regra", flag.ExitOnError)
	out := outFlag(fs)
	_ = fs.Parse(args)
	if *out == "" {
		return errNoOut
	}
	return os.WriteFile(*out, []byte(controls.YARARule), 0o644)
}
