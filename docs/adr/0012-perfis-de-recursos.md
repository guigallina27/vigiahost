# ADR-012: Perfis de recursos com travas no executor

**Status:** Aceito · **Data:** 22/10/2026 (aceito com o início da Fase 0)

**Contexto.** Servidores pequenos precisam de proteção contra sobrecarga; servidores grandes precisam liberar recursos.

**Decisão.** Perfis Leve, Padrão, Intensivo e próprios, aplicados como propriedades de cgroup; sugestão pelo hardware; ajuste em tempo real. O executor impõe reserva mínima para o sistema e exige confirmação explícita, reautenticação e auditoria para ultrapassá-la.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Perfis + travas no executor** | Média | Nenhum | Boa | Baixo |
| B. Limites fixos no código | Baixa | Nenhum | Ruim em servidores grandes | Lento demais ou pesado demais |
| C. Limites livres sem travas | Baixa | Nenhum | Boa | Configuração errada derruba o servidor |

**Consequências.** Mais fácil: adaptar a cada servidor. Mais difícil: explicar os efeitos na interface. Revisitar com o histórico real de execuções.

**Ações.** [x] Teste: pedido acima de 75% da RAM sem confirmação é recusado (`profile` e `run.adjust`). Ajuste em tempo real detalhado no [ADR-020](0020-ajuste-em-tempo-real-e-limitacao-por-pressao.md).
