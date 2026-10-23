# ADR-008: Objetos, achados, cobertura e ciclo de vida do achado

**Status:** Aceito · **Data:** 22/10/2026 (aceito com o início da Fase 0)

**Contexto.** Seis cópias do mesmo minerador viravam "seis malwares"; um estado único misturava falha, execução parcial e detecção.

**Decisão.** Objeto (SHA-256) com várias localizações; achados por motor e fonte de assinatura; execução avaliada em três dimensões (estado, achados, cobertura); ciclo de vida do achado separado da severidade.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Modelo de objetos e três dimensões** | Média | Nenhum | Boa | Baixo |
| B. Estado único por execução (v1) | Baixa | Nenhum | Boa | Esconde cobertura parcial |
| C. Relatórios brutos por ferramenta | Baixa | Nenhum | Ruim | Duplicidade e falsa confirmação |

**Consequências.** Mais fácil: cobertura honesta e contagem correta. Mais difícil: esquema e interface mais ricos. Revisitar quando a central consolidar vários servidores.

**Ações.** [ ] Glossário e componentes `SeverityBadge`/`StatusBadge` alinhados ao modelo.
