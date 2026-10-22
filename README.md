# VigiaHost

Plataforma de segurança para servidores Linux: varredura de malware, integridade, inspeção de processos e persistência, verificação por conta de hospedagem, agendamentos e alertas em uma interface web própria. Software livre sob [GPL-3.0](LICENSE).

> **Situação: Fase 0 (fundação), em desenvolvimento.** Ainda não detecta nada; não use em produção. O que existe hoje: core e executor com protocolo versionado, contrato OpenAPI, interface web base (design system, Visão geral com a saúde do serviço e do sistema), pacotes DEB/RPM testados em 10 distribuições e CI. Veja o [escopo](docs/escopo-v2.md), o [plano de implementação](docs/plano-implementacao.md) e as [decisões de arquitetura](docs/decisoes-arquitetura.md).

## Como funciona

| Componente | Usuário | Papel |
|---|---|---|
| `vigiahost` (serviço `vigiahost-core`) | `vigiahost`, sem privilégios | Interface web, API, agendador e banco SQLite (`/var/lib/vigiahost`) |
| `vigiahost-executor` | root, com capacidades mínimas | Única porta para operações privilegiadas: socket Unix `0660`, identidade do cliente pelo kernel (`SO_PEERCRED`) e só operações tipadas |

A interface escuta em `127.0.0.1:8743` (acesse por túnel SSH: `ssh -L 8743:127.0.0.1:8743 servidor`). A instalação do pacote não inicia os serviços ([ADR-015](docs/adr/0015-instalacao-sem-iniciar-servicos.md)):

```bash
sudo systemctl enable --now vigiahost-executor vigiahost-core
```

```bash
sudo vigiahost doctor
```

## Distribuições

Binários estáticos (`CGO_ENABLED=0`, `GOAMD64=v1`) para x86_64 e ARM64. Testadas a cada mudança: Ubuntu 22.04, 24.04 e 26.04; Debian 12 e 13; AlmaLinux 8, 9 e 10; Rocky Linux 9 e 10. Níveis de suporte no [escopo, seção 5](docs/escopo-v2.md).

## Desenvolvimento

Requisitos: Go 1.26.4 ou mais novo; Node.js 24 com corepack (`corepack enable pnpm` instala o pnpm fixado em `web/package.json`). Empacotar e rodar os testes com `-race` exige Linux.

| Comando | O que faz |
|---|---|
| `make web` | Build da interface em `internal/webui/dist` (embarcado no binário), com conferência de licenças |
| `make web-check` | Lint, tipos e testes unitários da interface |
| `make generate` | Regenera o servidor Go e os tipos TypeScript a partir de [`api/openapi.yaml`](api/openapi.yaml) |
| `make check-generated` | Falha se o código gerado não corresponder ao contrato |
| `make test` | Testes unitários |
| `make test-race` | Testes com detector de corrida (Linux) |
| `make vet` | `go vet` e formatação |
| `make vuln` | Vulnerabilidades conhecidas (govulncheck) |
| `make fuzz` | *Fuzzing* do protocolo do executor |
| `make package VERSION=x.y.z` | Pacotes DEB e RPM em `dist/`, sempre com a interface |

Interface em desenvolvimento, com recarga automática e a API de um core local (`vigiahost serve`) pelo proxy do Vite:

```bash
cd web && pnpm install && pnpm dev
```

O catálogo de componentes fica em `http://localhost:5173/catalogo` (só no servidor de desenvolvimento). Testes de acessibilidade com axe-core nos dois temas: `cd web && pnpm exec playwright install chromium && pnpm test:a11y`. Decisões da interface no [ADR-017](docs/adr/0017-base-da-interface.md).

### Laboratório

Os testes de sistema rodam em uma máquina isolada. No Windows, uma distribuição WSL dedicada, sem acesso aos discos do Windows e sem executar programas dele (`/etc/wsl.conf` com `automount` e `interop` desligados), com systemd, cgroup v2 e podman:

| Script | Onde roda | O que faz |
|---|---|---|
| [`test/lab/provision.sh`](test/lab/provision.sh) | Laboratório (dnf ou apt) | Instala ferramentas, o Go oficial e o Node.js LTS oficial conferidos por SHA-256, e o pnpm pelo corepack |
| [`test/lab/sync.sh`](test/lab/sync.sh) | Git Bash no Windows | Copia a árvore de trabalho para o laboratório |
| [`test/lab/test-lifecycle.sh`](test/lab/test-lifecycle.sh) | Laboratório com systemd | Instala, inicia, confere saúde, interface embarcada (CSP, compressão, cache) e política do executor, atualiza, volta de versão, remove e reinstala |
| [`test/lab/test-distros.sh`](test/lab/test-distros.sh) | Laboratório com podman | Ciclo de vida em contêineres das 10 distribuições |

O CI roda os mesmos scripts em um runner Ubuntu 24.04.

## Segurança

Para relatar vulnerabilidades, veja [SECURITY.md](SECURITY.md). Modelo de ameaças em [docs/modelo-ameacas.md](docs/modelo-ameacas.md).
