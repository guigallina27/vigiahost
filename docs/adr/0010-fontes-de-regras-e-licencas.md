# ADR-010: Fontes de regras e licenças

**Status:** Aceito · **Data:** 22/10/2026 (aceito com o início da Fase 0)

**Contexto.** Regras de terceiros têm licenças diversas (DRL 1.1, ELv2) e podem ser lentas ou maliciosas.

**Decisão.** Não embarcar regras de terceiros; baixar no servidor as fontes habilitadas, fixar versão, verificar hash, compilar e testar em unidade isolada e promover com controle positivo e corpus benigno; exibir autor, fonte, licença e link em cada achado.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Baixar, verificar e promover no cliente** | Média | Download periódico | Boa | Baixo |
| B. Embarcar regras de terceiros | Baixa | Nenhum | Boa | Violação de licença |
| C. Só regras próprias | Baixa | Nenhum | Ruim | Detecção pobre |

**Consequências.** Mais fácil: conformidade e retorno de conjunto. Mais difícil: o servidor precisa de acesso à fonte. Revisitar após a revisão jurídica da ELv2.

**Ações.** [ ] Revisão jurídica das licenças. [ ] Fluxo de promoção com troca atômica.
