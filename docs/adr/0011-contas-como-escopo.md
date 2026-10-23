# ADR-011: Contas do servidor como unidade de escopo

**Status:** Aceito · **Data:** 22/10/2026 (aceito com o início da Fase 0)

**Contexto.** Hospedagem é administrada por conta; o modelo do Imunify (lista de contas, verificação por conta) é o esperado pelos operadores.

**Decisão.** Contas derivadas do sistema (`getent passwd`, `UID_MIN`, diretório pessoal) desde a Fase 1B, enriquecidas pelos painéis na Fase 3. Agregação pelo UID e pelo caminho já registrados, sem nova leitura do disco. Conta como unidade de paralelismo e prioridade.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Sistema + enriquecimento por painel** | Média | Nenhum | Boa | Atribuição por UID ou caminho pode divergir em casos raros |
| B. Só pelo painel | Média | Nenhum | Boa | Sem contas em servidores sem painel |
| C. Só caminhos, sem conceito de conta | Baixa | Nenhum | Ruim | Investigação e priorização lentas |

**Consequências.** Mais fácil: verificar e priorizar por conta. Mais difícil: autorização por conta quando houver acesso de revendedores e clientes. Revisitar com a decisão sobre multiempresa.

**Ações.** [ ] Testes de escopo por conta e de isolamento entre contas.
