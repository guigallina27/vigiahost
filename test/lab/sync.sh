#!/usr/bin/env bash
# Copia a árvore de trabalho (arquivos versionados e novos, sem o que o git ignora) para a distribuição WSL do laboratório.
# O laboratório não monta os discos do Windows; a cópia entra pela entrada padrão do wsl.exe.
# Uso (Git Bash no Windows): test/lab/sync.sh [distribuição] [destino]
set -euo pipefail

distro="${1:-vigiahost-lab-alma9}"
dest="${2:-/root/src/vigiahost}"
root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"

git -C "$root" ls-files -z --cached --others --exclude-standard |
	tar -C "$root" --null --ignore-failed-read -T - -cf - |
	WSLENV='' wsl.exe -d "$distro" -- bash -c "rm -rf '$dest' && mkdir -p '$dest' && tar -xf - -C '$dest'"
echo "árvore copiada para $distro:$dest"
