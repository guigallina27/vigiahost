package scan

import (
	"slices"
	"testing"
)

func TestClassifyPeloConteudo(t *testing.T) {
	cases := []struct {
		head string
		name string
		want FileType
	}{
		{"\x7fELF\x02\x01\x01", "qualquer.jpg", TypeELF},
		{"<?php echo 1;", "index.php", TypePHP},
		{"\xff\xd8\xff\xe0JFIF<?php system($_GET['c']); ?>", "foto.jpg", TypePHP},
		{"\xff\xd8\xff\xe0JFIF\x00\x01", "foto.jpg", TypeImage},
		{"#!/usr/bin/env php\n<?php", "cli", TypePHP},
		{"#!/bin/sh\necho oi", "x", TypeScript},
		{"<!DOCTYPE html><html>", "a.txt", TypeHTML},
		{"<?xml version=\"1.0\"?><svg xmlns=", "a.svg", TypeImage},
		{"<?xml version=\"1.0\"?><feed>", "a.xml", TypeText},
		{"var a = 1;", "app.js", TypeJS},
		{"texto simples", "leia.txt", TypeText},
		{"PK\x03\x04", "plugin.zip", TypeArchive},
		{"\x00\x01\x02\x03\x00\x00", "dados", TypeBinary},
		{"", "vazio", TypeEmpty},
		{"%PDF-1.7", "a.pdf", TypeDoc},
		{"wOF2", "f.woff2", TypeFont},
		{"\x00\x00\x00\x18ftypmp42", "v.mp4", TypeMedia},
		{"<? echo 1; ?>", "short.php", TypePHP},
	}
	for _, c := range cases {
		if got := Classify([]byte(c.head), c.name); got != c.want {
			t.Errorf("Classify(%q, %q) = %s, esperado %s", c.head, c.name, got, c.want)
		}
	}
}

func TestNameFlags(t *testing.T) {
	rlo := string(rune(0x202e))
	zwsp := string(rune(0x200b))
	cases := []struct {
		name string
		typ  FileType
		want []NameFlag
	}{
		{"index.php", TypePHP, nil},
		{"foto" + rlo + "gpj.php", TypePHP, []NameFlag{FlagBidi}},
		{"quebra\nlinha.php", TypePHP, []NameFlag{FlagControlChars}},
		{"bytes-\xff\xfe.php", TypePHP, []NameFlag{FlagInvalidUTF8}},
		{"foto.jpg.php", TypePHP, []NameFlag{FlagDoubleExt}},
		{".cache.php", TypePHP, []NameFlag{FlagHiddenPHP}},
		{"avatar.png", TypePHP, []NameFlag{FlagTypeMismatch}},
		// Distribuídos por Drupal, Joomla e ferramentas de PHP: falsos positivos vistos no corpus benigno.
		{".ht.router.php", TypePHP, nil},
		{".phpstan-baseline.php", TypePHP, nil},
		{".phpstorm.meta.php", TypePHP, nil},
		{".php-cs-fixer.dist.php", TypePHP, nil},
		{"a" + zwsp + "b.php", TypePHP, []NameFlag{FlagInvisibleChars}},
	}
	for _, c := range cases {
		got := NameFlags(c.name, c.typ)
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("NameFlags(%q) = %v, faltou %s", c.name, got, w)
			}
		}
		if c.want == nil && len(got) > 0 {
			t.Errorf("NameFlags(%q) = %v, esperado nenhum", c.name, got)
		}
	}
}

func TestNameFlagsSemFalsoPositivoConhecido(t *testing.T) {
	for _, name := range []string{"symfony-ghost.svg.php", "index.php", "class-wp-user.php"} {
		for _, f := range NameFlags(name, TypePHP) {
			if f == FlagDoubleExt {
				t.Errorf("%q não deveria ser extensão dupla", name)
			}
		}
	}
}

func TestImagemComBytesAleatoriosNaoViraPHP(t *testing.T) {
	head := []byte("\xff\xd8\xff\xe0\x00\x10JFIF<? \x00\x01<?\n\x02")
	if got := Classify(head, "foto.jpg"); got != TypeImage {
		t.Fatalf("imagem com '<? ' por acaso: %s", got)
	}
}
