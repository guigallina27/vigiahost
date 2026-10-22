#!/usr/bin/env bash
# Cenário de laboratório para a análise de processos (fase 2): dois processos inofensivos (sleep) que rodam sem arquivo
# no disco, um a partir de memfd e outro de um arquivo apagado, ambos com o marcador do controle positivo no executável.
# Sobe cada um como unidade transitória do systemd, com prazo máximo, e confere o que a análise vai encontrar:
# o alvo de /proc/PID/exe e a detecção do marcador pelo YARA-X lendo /proc/PID/exe.
# Uso (como root no laboratório): scenario-memfd.sh [iniciar|conferir|parar]   (padrão: iniciar e conferir)
set -euo pipefail

cd "$(dirname "$0")/../.."
units=(vigiahost-lab-memfd vigiahost-lab-apagado)
lifetime=900 # segundos; as unidades terminam sozinhas mesmo se ninguém chamar "parar"

start() {
	mkdir -p /usr/local/libexec
	go build -o /usr/local/libexec/vigiahost-lab-memfdrun ./test/lab/memfdrun
	for u in "${units[@]}"; do
		systemctl stop "$u" 2>/dev/null || true
		systemctl reset-failed "$u" 2>/dev/null || true
	done
	systemd-run --quiet --unit=vigiahost-lab-memfd --property=RuntimeMaxSec=$lifetime \
		/usr/local/libexec/vigiahost-lab-memfdrun memfd $lifetime
	systemd-run --quiet --unit=vigiahost-lab-apagado --property=RuntimeMaxSec=$lifetime \
		/usr/local/libexec/vigiahost-lab-memfdrun apagado $lifetime
	sleep 1
}

check() {
	local rule fails=0
	rule="$(mktemp --suffix=.yar)"
	trap 'rm -f "$rule"' RETURN
	cp internal/controls/controle-positivo.yar "$rule"
	for u in "${units[@]}"; do
		local pid exe
		pid="$(systemctl show -P MainPID "$u")"
		if [[ -z $pid || $pid == 0 ]]; then
			echo "FALHA: $u não está rodando"; fails=$((fails + 1)); continue
		fi
		exe="$(readlink "/proc/$pid/exe")"
		case "$u:$exe" in
		vigiahost-lab-memfd:/memfd:vigiahost-controle\ \(deleted\)) ;;
		vigiahost-lab-apagado:/var/tmp/vigiahost-controle-apagado-*\ \(deleted\)) ;;
		*) echo "FALHA: $u (PID $pid) com exe inesperado: $exe"; fails=$((fails + 1)); continue ;;
		esac
		if yr scan --disable-console-logs "$rule" "/proc/$pid/exe" | grep -q '^vigiahost_controle_positivo '; then
			echo "ok: $u (PID $pid) roda de \"$exe\" e o YARA-X acha o marcador em /proc/$pid/exe"
		else
			echo "FALHA: YARA-X não achou o marcador em /proc/$pid/exe ($u)"; fails=$((fails + 1))
		fi
	done
	[[ $fails == 0 ]] && echo "CENÁRIO MEMFD CONFERIDO" || return 1
}

stop() {
	for u in "${units[@]}"; do systemctl stop "$u" 2>/dev/null || true; done
	rm -f /usr/local/libexec/vigiahost-lab-memfdrun
}

case "${1:-}" in
iniciar) start ;;
conferir) check ;;
parar) stop ;;
"") start; check ;;
*) echo "uso: $0 [iniciar|conferir|parar]" >&2; exit 2 ;;
esac
