# ADR-005: YARA-X como motor principal via CLI

**Status:** Aceito · **Data:** 22/10/2026 (aceito com o início da Fase 0)

**Contexto.** As distribuições trazem YARA de 4.1.3 a 4.5.5; o YARA original está só em manutenção.

**Decisão.** Distribuir o `yr` (YARA-X) em pacote próprio; regras pré-compiladas, saída NDJSON, `--cpu-limit` e limite de tempo. YARA 4.x apenas para memória de processos (Fase 3).

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. YARA-X via CLI distribuída** | Média | Um binário | Boa | Incompatibilidades de regras tratadas na compilação |
| B. YARA 4.x da distribuição | Baixa | Nenhum | Média | Comportamento diferente por distribuição |
| C. Biblioteca Go do YARA-X | Alta | Nenhum | Boa | Exige cgo e biblioteca C; quebra o binário estático |

**Consequências.** Mais fácil: comportamento igual em todas as distribuições. Mais difícil: acompanhar releases do YARA-X e traduzir regras antigas. Revisitar quando o YARA-X suportar varredura de processos.

**Ações.** [ ] *Golden files* por versão do `yr`. [ ] Medição de desempenho por regra.
