#!/usr/bin/env bash
# Teste de ponta a ponta real contra o VigiaHost instalado por pacote e ativo pelo systemd (core em 127.0.0.1:8743,
# executor root, ClamAV e YARA-X reais): compila test/lab/e2e e test/lab/memfdrun, sobe um processo de teste que roda
# de memfd (sleep inofensivo com o marcador do controle positivo) e roda o programa e2e, que percorre a API como a
# interface: primeiro acesso, segundo fator, varreduras, inspeção de processos, achados, verificação por conta (cria a
# conta de teste vh-e2e-conta), exceção, agendamento, cópia do banco, token de API e auditoria. O processo de teste é encerrado ao fim, com ou sem falha.
# Fase 1B: notificações (webhook assinado para um receptor local do próprio programa e2e, em 127.0.0.1), regras YARA
# e LMD (exige o LMD 2.x em /usr/local/maldetect; ligado só durante a etapa e devolvido ao estado original) e ajuste
# de CPU de uma varredura grande em andamento, conferido no cpu.max do cgroup, com as métricas e o comparativo.
#
# Repetível sem reinstalar: a primeira execução grava as credenciais do administrador e2e-admin em
# /root/.vigiahost-e2e.json (0600); as seguintes as reusam.
#
# Pré-requisitos: pacote instalado e ativado (vigiahost setup apply), motores (install-engines.sh) e corpus em
# /var/tmp/corpus/positivos e /var/tmp/corpus/benigno (test/corpus/gencorpus), Go para compilar.
# Uso (como root no laboratório): [VH_E2E_ACCOUNTS=500] test-e2e.sh [opções do programa e2e, ex.: -essential-only]
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

# Conta de hospedagem de teste para a verificação por conta (sem senha e sem shell de login).
account=vh-e2e-conta
if ! id "$account" >/dev/null 2>&1; then
	useradd --create-home --shell /sbin/nologin --comment "Conta de teste do VigiaHost" "$account" ||
		fail "criação da conta de teste $account"
fi
ok "conta de teste $account (UID $(id -u "$account"))"

# Conta nova a cada execução (nome inédito, apagada no fim): os arquivos de shell que o useradd copia de /etc/skel
# entram no inventário de persistência como novos sem virar achado, e a remoção da conta também não vira achado.
for old in $(getent passwd | cut -d: -f1 | grep '^vh-e2e-nova'); do
	userdel --remove "$old" 2>/dev/null || fail "remoção da conta $old de execução anterior"
done
newacct="vh-e2e-nova-$(date +%s)"
useradd --create-home --shell /sbin/nologin --comment "Conta nova do teste do VigiaHost" "$newacct" ||
	fail "criação da conta $newacct"
ok "conta nova $newacct criada (UID $(id -u "$newacct"))"

# Contas de carga (critério de saída da Fase 1B): VH_E2E_ACCOUNTS=500 cria vh-carga-001..500 que faltarem e liga a
# etapa de "verificar todas as contas" do programa e2e. As contas ficam no laboratório para as próximas execuções.
scale=()
if [[ ${VH_E2E_ACCOUNTS:-0} -gt 0 ]]; then
	created=0
	for i in $(seq -f %03g 1 "$VH_E2E_ACCOUNTS"); do
		id "vh-carga-$i" >/dev/null 2>&1 && continue
		useradd --create-home --shell /sbin/nologin --comment "Conta de carga do VigiaHost" "vh-carga-$i" ||
			fail "criação da conta de carga vh-carga-$i"
		created=$((created + 1))
	done
	ok "$VH_E2E_ACCOUNTS contas de carga vh-carga-NNN ($created criadas agora)"
	scale=(-scale-count "$VH_E2E_ACCOUNTS")
fi

cd "$(dirname "$0")/../.."
mkdir -p /usr/local/libexec
work="$(mktemp -d /usr/local/libexec/vigiahost-e2e.XXXXXX)"
cleanup() {
	systemctl stop "$unit" 2>/dev/null || true
	systemctl reset-failed "$unit" 2>/dev/null || true
	rm -rf "$work"
	userdel --remove "$newacct" 2>/dev/null || true
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

if ! "$work/e2e" -memfd-pid "$pid" -new-account "$newacct" "${scale[@]}" "$@"; then
	journal
	exit 1
fi
