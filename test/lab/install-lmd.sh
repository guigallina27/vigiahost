#!/usr/bin/env bash
# Instala o Linux Malware Detect (LMD) 2.0.1 no laboratório a partir do release oficial da rfxn, conferido pelo
# SHA-256 publicado pelo GitHub, sem tocar no clamd do laboratório:
#   - o install.sh do LMD copia as assinaturas rfxn.* para os diretórios do ClamAV e manda SIGUSR2 ao clamd; aqui
#     ele roda num namespace de montagem com tmpfs sobre esses diretórios e com um killall que não faz nada;
#   - a atualização periódica (cron maldet-sigup) e a varredura diária do LMD ficam desligadas, porque também
#     copiariam as assinaturas para o ClamAV e recarregariam o clamd usado pelos outros testes.
# O VigiaHost nunca instala o LMD: em servidores reais quem instala é o administrador. Uso: install-lmd.sh (root).
set -euo pipefail

LMD_VERSION=2.0.1
# Campo digest do asset maldet-2.0.1.tar.gz no release v2.0.1 (API do GitHub), consultado em 22/10/2026.
LMD_SHA256=26674c72208a4c32ae4ed8770a2b5c036b35c0894a4812450df11c5a53d7d8e5
URL="https://github.com/rfxn/linux-malware-detect/releases/download/v${LMD_VERSION}/maldet-${LMD_VERSION}.tar.gz"

log() { printf '[lmd] %s\n' "$*"; }

if [[ -x /usr/local/maldetect/maldet ]] && /usr/local/maldetect/maldet --version 2>/dev/null | grep -q "v${LMD_VERSION}"; then
	log "LMD ${LMD_VERSION} já instalado"
	exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/maldet.tar.gz" "$URL"
echo "${LMD_SHA256}  $tmp/maldet.tar.gz" | sha256sum -c --quiet -
mkdir "$tmp/src" "$tmp/bin"
tar -xzf "$tmp/maldet.tar.gz" -C "$tmp/src"
src="$(find "$tmp/src" -maxdepth 2 -name install.sh -printf '%h\n' | head -1)"
printf '#!/bin/sh\nexit 0\n' >"$tmp/bin/killall"
chmod 0755 "$tmp/bin/killall"

clamdirs=()
for d in /usr/local/cpanel/3rdparty/share/clamav /var/lib/clamav /var/clamav /usr/share/clamav /usr/local/share/clamav; do
	[[ -d $d ]] && clamdirs+=("$d")
done
log "instalando a partir de $URL (diretórios do ClamAV protegidos: ${clamdirs[*]:-nenhum})"
unshare -m --propagation private bash -c '
	set -e
	for d in "$@"; do mount -t tmpfs vigiahost-lab-lmd "$d"; done
	cd "'"$src"'" && PATH="'"$tmp/bin"':$PATH" ./install.sh
' _ "${clamdirs[@]}"

conf=/usr/local/maldetect/conf.maldet
set_conf() { sed -i -E "s|^$1=.*|$1=\"$2\"|" "$conf"; grep -q "^$1=" "$conf" || echo "$1=\"$2\"" >>"$conf"; }
set_conf sigup_interval 0
set_conf cron_daily_scan 0
set_conf autoupdate_signatures 0
set_conf autoupdate_version 0
set_conf scan_clamscan 0
set_conf quarantine_hits 0
set_conf email_alert 0
rm -f /etc/cron.d/maldet-sigup
# O monitor por inotify do LMD não é usado pelo VigiaHost.
systemctl disable --now maldet.service >/dev/null 2>&1 || true
for d in "${clamdirs[@]}"; do
	if compgen -G "$d/rfxn.*" >/dev/null || compgen -G "$d/lmd.user.*" >/dev/null; then
		log "ATENÇÃO: assinaturas do LMD encontradas em $d; remova-as manualmente" >&2
	fi
done
log "pronto: $(/usr/local/maldetect/maldet --version 2>/dev/null | head -1)"
