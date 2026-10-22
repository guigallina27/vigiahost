// Package scan implementa a varredura de arquivos da execução: inventário único do escopo, classificação pelo
// conteúdo, cache, distribuição dos descritores aos motores e gravação do relatório (escopo, seção 6.2).
// Roda dentro da unidade transitória criada pelo executor, nunca no processo do executor.
package scan

import (
	"bytes"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

// FileType é o tipo de conteúdo lido nos primeiros bytes, não na extensão.
type FileType string

const (
	TypeELF     FileType = "elf"
	TypePHP     FileType = "php"
	TypeScript  FileType = "script" // shebang (#!)
	TypeHTML    FileType = "html"
	TypeJS      FileType = "js"
	TypeArchive FileType = "archive"
	TypeImage   FileType = "image"
	TypeFont    FileType = "font"
	TypeMedia   FileType = "media"
	TypeDoc     FileType = "document"
	TypeText    FileType = "text"
	TypeBinary  FileType = "binary"
	TypeEmpty   FileType = "empty"
)

// HeadSize é quanto do início do arquivo a classificação lê.
const HeadSize = 4096

type magic struct {
	prefix []byte
	typ    FileType
}

var magics = []magic{
	{[]byte("\x7fELF"), TypeELF},
	{[]byte("PK\x03\x04"), TypeArchive},
	{[]byte("PK\x05\x06"), TypeArchive},
	{[]byte("\x1f\x8b"), TypeArchive},
	{[]byte("BZh"), TypeArchive},
	{[]byte("\xfd7zXZ\x00"), TypeArchive},
	{[]byte("7z\xbc\xaf\x27\x1c"), TypeArchive},
	{[]byte("Rar!\x1a\x07"), TypeArchive},
	{[]byte("\x28\xb5\x2f\xfd"), TypeArchive}, // zstd
	{[]byte("\xff\xd8\xff"), TypeImage},
	{[]byte("\x89PNG\r\n\x1a\n"), TypeImage},
	{[]byte("GIF87a"), TypeImage},
	{[]byte("GIF89a"), TypeImage},
	{[]byte("BM"), TypeImage},
	{[]byte("II*\x00"), TypeImage},
	{[]byte("MM\x00*"), TypeImage},
	{[]byte("\x00\x00\x01\x00"), TypeImage}, // ico
	{[]byte("wOFF"), TypeFont},
	{[]byte("wOF2"), TypeFont},
	{[]byte("\x00\x01\x00\x00\x00"), TypeFont}, // ttf
	{[]byte("OTTO"), TypeFont},
	{[]byte("%PDF-"), TypeDoc},
	{[]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), TypeDoc}, // OLE (doc, xls)
	{[]byte("ID3"), TypeMedia},
	{[]byte("OggS"), TypeMedia},
	{[]byte("fLaC"), TypeMedia},
	{[]byte("\x1a\x45\xdf\xa3"), TypeMedia}, // webm/mkv
}

// Classify devolve o tipo do conteúdo a partir do início do arquivo. O nome só desempata texto (ex.: .js).
func Classify(head []byte, name string) FileType {
	if len(head) == 0 {
		return TypeEmpty
	}
	for _, m := range magics {
		if bytes.HasPrefix(head, m.prefix) {
			// Imagem com código PHP embutido continua sendo PHP para o roteamento: é o disfarce clássico.
			// Em binários só valem as aberturas explícitas: "<? " aparece por acaso em bytes aleatórios.
			if (m.typ == TypeImage || m.typ == TypeDoc) && containsExplicitPHP(head) {
				return TypePHP
			}
			return m.typ
		}
	}
	if len(head) >= 12 && string(head[4:8]) == "ftyp" {
		return TypeMedia // mp4, mov, heic
	}
	if len(head) >= 12 && string(head[0:4]) == "RIFF" {
		if string(head[8:12]) == "WEBP" {
			return TypeImage
		}
		return TypeMedia
	}
	if bytes.HasPrefix(head, []byte("#!")) {
		if bytes.Contains(firstLine(head), []byte("php")) {
			return TypePHP
		}
		return TypeScript
	}
	if containsPHPOpen(head) {
		return TypePHP
	}
	if !looksText(head) {
		return TypeBinary
	}
	trimmed := bytes.TrimLeft(head, " \t\r\n\xef\xbb\xbf")
	lower := bytes.ToLower(trimmed[:min(len(trimmed), 64)])
	if bytes.HasPrefix(lower, []byte("<!doctype html")) || bytes.HasPrefix(lower, []byte("<html")) {
		return TypeHTML
	}
	if bytes.HasPrefix(lower, []byte("<svg")) || bytes.HasPrefix(lower, []byte("<?xml")) {
		if bytes.Contains(bytes.ToLower(head), []byte("<svg")) {
			return TypeImage
		}
		return TypeText
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".js", ".mjs", ".cjs":
		return TypeJS
	case ".htm", ".html":
		return TypeHTML
	case ".sh", ".bash", ".py", ".pl", ".rb":
		return TypeScript
	}
	return TypeText
}

func containsExplicitPHP(head []byte) bool {
	l := bytes.ToLower(head)
	return bytes.Contains(l, []byte("<?php")) || bytes.Contains(l, []byte("<?=$"))
}

func containsPHPOpen(head []byte) bool {
	l := bytes.ToLower(head)
	if bytes.Contains(l, []byte("<?php")) || bytes.Contains(l, []byte("<?=")) {
		return true
	}
	// "<?" seguido de espaço: short tag. Evita "<?xml".
	for i := 0; ; {
		j := bytes.Index(l[i:], []byte("<?"))
		if j < 0 {
			return false
		}
		k := i + j + 2
		if k < len(l) && (l[k] == ' ' || l[k] == '\n' || l[k] == '\r' || l[k] == '\t') {
			return true
		}
		i = k
	}
}

func firstLine(b []byte) []byte {
	line, _, _ := bytes.Cut(b, []byte{'\n'})
	return line
}

// looksText considera texto quando não há NUL e quase todos os bytes são imprimíveis ou UTF-8 válido.
func looksText(b []byte) bool {
	if bytes.IndexByte(b, 0) >= 0 {
		return false
	}
	bad := 0
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		if r == utf8.RuneError && size == 1 {
			bad++ // Latin-1 e outras codificações antigas ainda são texto
			continue
		}
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' && r != '\f' && r != 0x1b {
			bad += 4
		}
	}
	return bad < 32
}

// NameFlag marca nomes que merecem atenção por si só (escopo, seção 6.2, item 2).
type NameFlag string

const (
	FlagControlChars   NameFlag = "control_chars"
	FlagBidi           NameFlag = "bidi"
	FlagInvalidUTF8    NameFlag = "invalid_utf8"
	FlagDoubleExt      NameFlag = "double_extension"
	FlagHiddenPHP      NameFlag = "hidden_php"
	FlagTypeMismatch   NameFlag = "type_mismatch"
	FlagInvisibleChars NameFlag = "invisible_chars"
)

var imageExts = map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".ico": true, ".webp": true, ".bmp": true, ".svg": true}

var scriptExts = map[string]bool{".php": true, ".phtml": true, ".php5": true, ".php7": true, ".phar": true, ".pht": true, ".shtml": true}

// NameFlags analisa o nome (só o último componente) junto do tipo detectado.
func NameFlags(name string, typ FileType) []NameFlag {
	var flags []NameFlag
	if !utf8.ValidString(name) {
		flags = append(flags, FlagInvalidUTF8)
	}
	var ctrl, bidi, invisible bool
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			ctrl = true
		case isBidi(r):
			bidi = true
		case r == 0x200b || r == 0x200c || r == 0x200d || r == 0x2060 || r == 0xfeff || r == 0x00ad:
			invisible = true
		case unicode.Is(unicode.Cf, r):
			invisible = true
		}
	}
	if ctrl {
		flags = append(flags, FlagControlChars)
	}
	if bidi {
		flags = append(flags, FlagBidi)
	}
	if invisible {
		flags = append(flags, FlagInvisibleChars)
	}
	lower := strings.ToLower(name)
	ext := path.Ext(lower)
	// SVG fica de fora: frameworks geram "imagem.svg.php" legítimos (ex.: páginas de erro do Symfony).
	if inner := path.Ext(strings.TrimSuffix(lower, ext)); inner != "" && inner != ".svg" && scriptExts[ext] && imageExts[inner] {
		flags = append(flags, FlagDoubleExt) // foto.jpg.php
	}
	if strings.HasPrefix(name, ".") && scriptExts[ext] {
		flags = append(flags, FlagHiddenPHP)
	}
	if typ == TypePHP && imageExts[ext] {
		flags = append(flags, FlagTypeMismatch) // código PHP com extensão de imagem
	}
	return flags
}

func isBidi(r rune) bool {
	return (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f || r == 0x061c
}
