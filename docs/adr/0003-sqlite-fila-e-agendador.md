# ADR-003: SQLite com fila própria e agendador orientado ao banco

**Status:** Aceito · **Data:** 22/10/2026 (aceito com o início da Fase 0)

**Contexto.** Agendamentos e execuções precisam sobreviver a reinícios sem duplicar; o produto não deve exigir outro serviço de banco no servidor do cliente.

**Decisão.** SQLite (WAL, um escritor, `STRICT`, FTS5) com tabela de jobs (*lease*, *heartbeat*, idempotência, máquina de estados) e agendador com `next_run_at` persistido e chave única `(agendamento, horário previsto)`. goqite como referência.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. SQLite + fila e agendador próprios** | Média | Nenhum serviço extra | 1 milhão de arquivos com inventário fora do banco | Baixo |
| B. gocron em memória + SQLite | Baixa | Nenhum | Boa | Horários perdidos e duplicidade após reinício |
| C. PostgreSQL local | Média | Serviço extra em cada servidor | Alta | Operação e conflito com bancos do cliente |

**Trade-offs.** A aceita um único escritor (gravações agrupadas) para não depender de outro serviço.

**Consequências.** Mais fácil: backup com `VACUUM INTO`, instalação simples. Mais difícil: concorrência de escrita exige disciplina. Revisitar na central (PostgreSQL, ADR-001).

**Ações.** [ ] Testes de recuperação com `kill -9` e salto de relógio (`testing/synctest`).
