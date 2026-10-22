# ADR-001: Go + React embarcado; central sem Next.js

**Status:** Aceito · **Data:** 22/10/2026 (aceito com o início da Fase 0)

**Contexto.** O produto é instalado por um comando em servidores de clientes, de EL8 a Ubuntu 26.04, e precisa de consumo baixo em repouso. A interface é rica (tabelas grandes, tempo real). A central virá depois e deve reaproveitar a interface.

**Decisão.** Binário Go estático (`CGO_ENABLED=0`) com a interface React (Vite) embarcada. A central usa Go + PostgreSQL e os mesmos pacotes React.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Go + React embarcado** | Média | Baixo: um binário, sem Node | Boa para o painel local | Baixo |
| B. Go (API) + Next.js | Alta | Node em produção em cada servidor | Boa | Duas pilhas de interface |
| C. Backend em Python ou Node | Média | Interpretador e dependências no servidor; mais memória | Média | Dependência das versões da distribuição |

**Trade-offs.** A perde renderização no servidor, que não é necessária num painel autenticado; ganha implantação simples e uma única pilha de interface.

**Consequências.** Mais fácil: instalar, atualizar e auditar um binário; compartilhar componentes com a central. Mais difícil: o CI mantém duas cadeias de build (Go e pnpm). Revisitar se a central exigir renderização no servidor.

**Ações.** [ ] Monorepo com pacote de componentes compartilhado. [ ] Recursos embarcados com hash no nome e cache imutável.
