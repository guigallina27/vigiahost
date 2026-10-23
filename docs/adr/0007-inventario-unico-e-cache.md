# ADR-007: Inventário único e cache por inode, `ctime` e versão

**Status:** Aceito · **Data:** 22/10/2026 (aceito com o início da Fase 0)

**Contexto.** Cada ferramenta percorria o disco separadamente; não havia progresso real nem cobertura comparável.

**Decisão.** Um percurso por execução, classificação por conteúdo, distribuição do mesmo descritor aos motores e cache com chave `(dispositivo, inode, tamanho, mtime, ctime)` + versão de assinaturas/regras.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Inventário único + cache** | Alta | I/O reduzido | Boa | Corridas e arquivos especiais exigem cuidado |
| B. Cada ferramenta percorre o disco | Baixa | I/O multiplicado | Ruim | Sem cobertura comparável |
| C. Só monitoramento em tempo real | Alta | Agente residente | Boa | Não cobre o estado inicial; fica como complemento na Fase 3 |

**Consequências.** Mais fácil: rotina incremental, deduplicação, ordem por risco. Mais difícil: regras de invalidação do cache. Revisitar com o monitoramento contínuo.

**Ações.** [ ] Testes de FIFO, socket, FUSE e troca de arquivo durante a leitura.
