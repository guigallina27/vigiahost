#!/usr/bin/env bash
# Prepara uma máquina de laboratório (WSL, VM ou contêiner) para compilar e testar o VigiaHost.
# Uso: provision.sh [--sem-podman]
# Suporta famílias RHEL (dnf) e Debian (apt). Instala Go oficial conferido pelo SHA-256 publicado em go.dev.
set -euo pipefail

with_podman=1
[[ "${1:-}" == "--sem-podman" ]] && with_podman=0

log() { printf '[provision] %s\n' "$*"; }

if command -v dnf >/dev/null 2>&1; then
	pkgs=(git tar gzip xz make gcc gnupg2 rpm-sign jq procps-ng iproute findutils diffutils file curl)
	((with_podman)) && pkgs+=(podman)
	log "instalando pacotes com dnf"
	dnf -y -q install "${pkgs[@]}"
elif command -v apt-get >/dev/null 2>&1; then
	pkgs=(git tar gzip xz-utils make gcc gnupg jq procps iproute2 findutils diffutils file curl ca-certificates)
	((with_podman)) && pkgs+=(podman)
	log "instalando pacotes com apt"
	export DEBIAN_FRONTEND=noninteractive
	apt-get -qq update
	apt-get -qq -y install "${pkgs[@]}"
else
	log "gerenciador de pacotes não suportado" >&2
	exit 1
fi

arch="$(uname -m)"
case "$arch" in
x86_64) goarch=amd64 ;;
aarch64) goarch=arm64 ;;
*)
	log "arquitetura não suportada: $arch" >&2
	exit 1
	;;
esac

release_json="$(curl -fsSL 'https://go.dev/dl/?mode=json')"
go_version="$(jq -r '[.[] | select(.stable)][0].version' <<<"$release_json")"
go_sha256="$(jq -r --arg a "$goarch" '[.[] | select(.stable)][0].files[] | select(.os == "linux" and .arch == $a and .kind == "archive") | .sha256' <<<"$release_json")"

if command -v go >/dev/null 2>&1 && [[ "$(go env GOVERSION)" == "$go_version" ]]; then
	log "Go $go_version já instalado"
else
	log "baixando $go_version ($goarch)"
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
	curl -fsSL -o "$tmp/go.tgz" "https://go.dev/dl/${go_version}.linux-${goarch}.tar.gz"
	echo "${go_sha256}  $tmp/go.tgz" | sha256sum -c --quiet -
	rm -rf /usr/local/go
	tar -C /usr/local -xzf "$tmp/go.tgz"
	ln -sf /usr/local/go/bin/go /usr/local/bin/go
	ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
fi

log "pronto: $(go version)"
