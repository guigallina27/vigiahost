# ADR-019: Consultas SQL escritas à mão em vez do sqlc

**Status:** Aceito · **Data:** 22/10/2026 (decidido na implementação da Fase 1A)

**Contexto.** O escopo previa o sqlc para gerar o acesso ao SQLite a partir das consultas. Na Fase 1A as consultas
reais apareceram: fila com `UPDATE … RETURNING`, ingestão de achados com deduplicação e offset na mesma transação,
filtros dinâmicos (estado, severidade, busca em qualquer cópia do arquivo, paginação por cursor), auditoria encadeada
por hash e agendamento com `ON CONFLICT`. Boa parte é dinâmica ou depende de transações que atravessam várias consultas.

**Decisão.** Consultas escritas à mão em `internal/store` com `database/sql`, sempre parametrizadas (`?`), uma
conexão única com WAL e transações explícitas (`DB.tx`). Constantes de SQL que repetem regras do Go (ex.: a lista de
estados finais) têm teste que confere a equivalência. O sqlc deixa a lista de ferramentas do projeto.

| Opção | Complexidade | Custo | Risco |
|---|---|---|---|
| **A. SQL à mão em `internal/store`** | Média | Nenhum | Erro de digitação em coluna só aparece no teste — mitigado pelos testes de cada consulta |
| B. sqlc | Média | Mais uma ferramenta no build | Filtros dinâmicos e transações compostas fogem do modelo; acabaria misturando gerado e manual |
| C. ORM | Baixa no início | Dependência grande | SQL opaco em código de segurança; difícil auditar |

**Consequências.** Mais fácil: consultas legíveis num lugar só, sem passo de geração. Mais difícil: a checagem de
tipos das colunas passa a depender dos testes de `internal/store` (todos rodam com o SQLite real). Revisitar se o
número de consultas estáticas crescer muito.
