#!/usr/bin/env bash
# Valida o VigiaHost em ARM64 (aarch64) num laboratório x86_64:
#   1. testes Go compilados para arm64 e executados pelo emulador qemu-aarch64-static (modo usuário);
#   2. binários e pacotes DEB/RPM arm64, com a arquitetura conferida no ELF e nos metadados dos pacotes;
#   3. o binário arm64 rodando sob o emulador (vigiahost version).
# O emulador vem do pacote do Fedora, conferido pelo SHA-256 fixado abaixo (e assinado com a chave do Fedora 44).
# Ele é só extraído, nunca instalado: o pacote registraria o qemu no binfmt_misc, que no WSL é do kernel compartilhado
# por todas as distribuições. Sem binfmt, o emulador é chamado explicitamente (go test -exec).
# Não substitui o job nativo do CI (ubuntu-24.04-arm): o qemu de modo usuário não emula o kernel, então /proc,
# systemd e o detector de race não são exercitados aqui. Uso (como root no laboratório): test-arm64.sh
set -euo pipefail

QEMU_RPM=qemu-user-static-aarch64-10.2.2-1.fc44.x86_64.rpm
QEMU_URL=https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Everything/x86_64/os/Packages/q/$QEMU_RPM
QEMU_SHA256=ed4478c36caab71ac0c252e0498a16dd02dd8c093ae0ec0b5b37f9a7f4999121
QEMU=/opt/vigiahost-lab/bin/qemu-aarch64-static

log() { printf '[arm64] %s\n' "$*"; }
cd "$(dirname "$0")/../.."

if [[ ! -x $QEMU ]]; then
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
	log "baixando $QEMU_RPM"
	curl -fsSL -o "$tmp/$QEMU_RPM" "$QEMU_URL"
	echo "$QEMU_SHA256  $tmp/$QEMU_RPM" | sha256sum -c --quiet -
	(cd "$tmp" && rpm2cpio "$QEMU_RPM" | cpio -id --quiet ./usr/bin/qemu-aarch64-static)
	install -D -m 0755 "$tmp/usr/bin/qemu-aarch64-static" "$QEMU"
fi
log "$("$QEMU" --version | head -1)"

log "testes Go (arm64 sob emulação)"
CGO_ENABLED=0 GOARCH=arm64 go test -count=1 -exec "$QEMU" ./...

log "binários e pacotes arm64"
make package GOARCH=arm64 >/dev/null
for b in dist/arm64/vigiahost dist/arm64/vigiahost-executor; do
	machine="$(readelf -h "$b" | awk -F: '/Machine/ {gsub(/^ +/, "", $2); print $2}')"
	[[ $machine == AArch64 ]] || { log "FALHA: $b é $machine"; exit 1; }
done
"$QEMU" dist/arm64/vigiahost version
rpm_arch="$(rpm -qp --qf '%{ARCH}' dist/*.aarch64.rpm)"
deb_arch="$(ar p dist/*_arm64.deb control.tar.gz | tar -xzO ./control | awk '/^Architecture:/ {print $2}')"
[[ $rpm_arch == aarch64 && $deb_arch == arm64 ]] || { log "FALHA: arquitetura nos pacotes: rpm=$rpm_arch deb=$deb_arch"; exit 1; }
ls -l dist/*.aarch64.rpm dist/*_arm64.deb
log "ARM64 CONFERIDO"
