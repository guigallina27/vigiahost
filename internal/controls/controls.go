// Package controls define os controles positivos inofensivos usados pelo autoteste dos motores
// (escopo, seção 7.4) e pelo corpus de testes: o arquivo de teste EICAR e um marcador YARA inerte.
//
// Nada aqui é malware. O EICAR é montado em tempo de execução, e não guardado inteiro no código-fonte,
// para que antivírus em máquinas de desenvolvimento não coloquem o repositório em quarentena.
package controls

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
)

// Marker é o texto que a regra YARA do controle positivo procura.
const Marker = "VIGIAHOST-CONTROLE-POSITIVO-INERTE-7f3c9a1e"

// YARARuleName é o nome da regra que reconhece o Marker.
const YARARuleName = "vigiahost_controle_positivo"

// ClamAVEICARName é o nome com que o ClamAV reporta o arquivo de teste EICAR.
const ClamAVEICARName = "Eicar-Test-Signature"

// YARARule é o código-fonte da regra do controle positivo.
//
//go:embed controle-positivo.yar
var YARARule string

// SHA-256 do arquivo de teste EICAR padrão (68 bytes), publicado em eicar.org.
const eicarSHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

// Partes do EICAR, na ordem inversa, para o arquivo-fonte não conter a sequência completa.
var eicarParts = [...]string{
	"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
	`X5O!P%@AP[4\PZX54(P^)7CC)7}$`,
}

// EICAR devolve o arquivo de teste EICAR padrão e confere seu SHA-256.
func EICAR() []byte {
	b := []byte(eicarParts[1] + eicarParts[0])
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != eicarSHA256 {
		panic(fmt.Sprintf("controls: EICAR montado com hash inesperado %x", sum))
	}
	return b
}

// MarkerFile devolve um arquivo de texto com o marcador, para o controle positivo do YARA.
func MarkerFile() []byte {
	return []byte("Controle positivo inerte do VigiaHost; este arquivo não é malware.\n" + Marker + "\n")
}

// NegativeFile devolve um arquivo que nenhum motor deve acusar (controle negativo).
func NegativeFile() []byte {
	return []byte("Controle negativo do VigiaHost: arquivo de texto comum, sem marcador.\n")
}
