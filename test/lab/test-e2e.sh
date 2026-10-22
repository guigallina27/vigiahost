#!/usr/bin/env bash
# Teste de ponta a ponta real contra o VigiaHost instalado por pacote e ativo pelo systemd (core em 127.0.0.1:8743,
# executor root, ClamAV e YARA-X reais): compila test/lab/e2e e test/lab/memfdrun, sobe um processo de teste que roda
# de memfd (sleep inofensivo com o marcador do controle positivo) e roda o programa e2e, que percorre a API como a
# interface: primeiro acesso, segundo fator, varreduras, inspeção de processos, achados, exceção, agendamento, cópia do
# banco, token de API e auditoria. O processo de teste é encerrado ao fim, com ou sem falha.
#
# Repetível sem reinstalar: a primeira execução grava as credenciais do administrador e2e-admin em
# /root/.vigiahost-e2e.json (0600); as seguintes as reusam.
#
# Pré-requisitos: pacote instalado e ativado (vigiahost setup apply), motores (install-engines.sh) e corpus em
# /var/tmp/corpus/positivos e /var/tmp/corpus/benigno (test/corpus/gencorpus), Go para compilar.
# Uso (como root no laboratório): test-e2e.sh [opções do programa e2e, ex.: -essential-only -run-timeout 20m]
set -euo pipefail

unit=vigiahost-e2e-memfd
lifetime=3600 # segundos; a unidade termina sozinha mesmo se o roteiro for interrompido sem limpeza

journal() { journalctl -u vigiahost-core -u vigiahost-executor --no-pager -n 60 >&2 || true; }
fail() {
	echo "FALHA: $*" >&2
	journal
	exit 1
}
ok() { echo "ok: $*"; }

[[ $EUID == 0 ]] || fail "rode como root"
[[ -d /run/systemd/system ]] || fail "este teste exige systemd em execução"
systemctl is-active --quiet vigiahost-core || fail "vigiahost-core não está ativo (vigiahost setup apply)"
systemctl is-active --quiet vigiahost-executor || fail "vigiahost-executor não está ativo"
command -v go >/dev/null 2>&1 || fail "Go não encontrado (necessário para compilar o teste)"
for d in /var/tmp/corpus/positivos /var/tmp/corpus/benigno; do
	[[ -d $d ]] || fail "corpus ausente: $d"
done

cd "$(dirname "$0")/../.."
mkdir -p /usr/local/libexec
work="$(mktemp -d /usr/local/libexec/vigiahost-e2e.XXXXXX)"
cleanup() {
	systemctl stop "$unit" 2>/dev/null || true
	systemctl reset-failed "$unit" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

go build -o "$work/e2e" ./test/lab/e2e || fail "compilação de test/lab/e2e"
go build -o "$work/memfdrun" ./test/lab/memfdrun || fail "compilação de test/lab/memfdrun"
ok "programas do teste compilados"

# Processo de teste sem arquivo no disco: só um sleep, com prazo máximo de vida.
systemctl stop "$unit" 2>/dev/null || true
systemctl reset-failed "$unit" 2>/dev/null || true
systemd-run --quiet --unit="$unit" --property=RuntimeMaxSec=$lifetime "$work/memfdrun" memfd $lifetime ||
	fail "processo de teste memfd não subiu"
pid=0
for _ in $(seq 1 20); do
	pid="$(systemctl show -P MainPID "$unit")"
	if [[ -n $pid && $pid != 0 && "$(readlink "/proc/$pid/exe" 2>/dev/null)" == "/memfd:vigiahost-controle (deleted)" ]]; then
		break
	fi
	sleep 0.5
done
exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
[[ $exe == "/memfd:vigiahost-controle (deleted)" ]] || fail "processo de teste memfd (PID $pid) com exe inesperado: $exe"
ok "processo de teste sem arquivo no ar: PID $pid roda de \"$exe\""

if ! "$work/e2e" -memfd-pid "$pid" "$@"; then
	journal
	exit 1
fi
