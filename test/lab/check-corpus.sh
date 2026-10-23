#!/usr/bin/env bash
# Confere os corpus gerados pelo gencorpus com o ClamAV e o YARA-X reais (instalados por install-engines.sh):
#   - positivos: cada arquivo detectado exatamente pelo motor esperado, e nada nos controles negativos;
#   - sintetico: o YARA-X acha exatamente os marcadores plantados; o ClamAV não acha nada;
#   - benigno:   nenhum achado (cada achado seria falso positivo).
# Os arquivos chegam aos motores por descritor (/dev/fd/N), nunca pelo nome; veja test/corpus/gencorpus/verify.go.
# Uso: check-corpus.sh DIRETÓRIO_DOS_CORPUS (com positivos/, sintetico/ e/ou benigno/)
set -euo pipefail

root="${1:?informe o diretório dos corpus}"
cd "$(dirname "$0")/../.."
go build -o /tmp/gencorpus ./test/corpus/gencorpus
fails=0
for kind in positivos sintetico benigno; do
	[[ -d $root/$kind ]] || continue
	/tmp/gencorpus verificar -dir "$root/$kind" || fails=$((fails + 1))
done
[[ $fails == 0 ]] && echo "CORPUS CONFERIDO" || { echo "$fails corpus com divergência"; exit 1; }
