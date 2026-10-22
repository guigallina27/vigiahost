# ADR-013: Integrações complementares opcionais como entrada não confiável

**Status:** Aceito · **Data:** 22/10/2026 (aceito com o início da Fase 0)

**Contexto.** OSV-Scanner, Wordfence Intelligence, abuse.ch e Falco ampliam a visão (vulnerabilidades e comportamento), mas trazem dados e termos de terceiros.

**Decisão.** Todas opcionais; bases baixadas por unidade separada com rede, verificadas e versionadas; consultas locais; chaves como segredos; dados e eventos tratados como entrada não confiável. Falco desligado por padrão, como serviço próprio fora do executor.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Opcionais, locais e não confiáveis** | Média | Só o que for ativado | Boa | Baixo |
| B. Todas ativas por padrão | Média | Alto (Falco residente, downloads) | Média | Termos de uso e consumo |
| C. Delegar a agentes externos (osquery, Wazuh) | Baixa | Outro agente residente | Boa | Sobreposição e dependência externa |

**Consequências.** Mais fácil: o núcleo funciona sem terceiros. Mais difícil: manter adaptadores e acompanhar termos. Revisitar a cada mudança de termos dos feeds.

**Ações.** [ ] Registro de termos e atribuições por fonte. [ ] *Fuzzing* dos interpretadores de feeds e eventos.
