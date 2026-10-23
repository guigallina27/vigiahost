# ADR-004: Execuções em unidades systemd transitórias

**Status:** Aceito · **Data:** 22/10/2026 (aceito com o início da Fase 0)

**Contexto.** Varreduras não podem travar o servidor e precisam de pausa, cancelamento e recuperação após reinício do executor.

**Decisão.** Cada execução roda em unidade transitória criada via D-Bus (`coreos/go-systemd`), com nome determinístico, limites de cgroup, sem rede e somente leitura.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Unidades transitórias** | Média | Nenhum | Boa | Baixo; EL8 (cgroup v1) com funções limitadas |
| B. Processos filhos com `nice`/`ionice`/`setrlimit` | Baixa | Nenhum | Média | Sem limite de memória do grupo nem pausa confiável |
| C. Contêineres (podman) | Alta | Runtime de contêiner | Boa | Dependência pesada e incomum em hospedagem |

**Trade-offs.** A depende de systemd (premissa do produto) e de cgroup v2 para pausa e `io.max`.

**Consequências.** Mais fácil: cancelar a árvore inteira, ajustar limites em tempo real, reconciliar pelo nome. Mais difícil: testar nas variações de versão do systemd. Revisitar se houver demanda por sistemas sem systemd.

**Ações.** [ ] Matriz de capacidades detectadas (seção 5.3 do escopo) exibida na interface.
