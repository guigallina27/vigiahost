# ADR-002: Separação core/executor com política no executor

**Status:** Aceito · **Data:** 22/10/2026 (aceito com o início da Fase 0)

**Contexto.** Ler arquivos de todas as contas, mover para quarentena e encerrar processos exigem root. O serviço web é a superfície mais exposta.

**Decisão.** `vigiahost-core` sem privilégios; `vigiahost-executor` root, mínimo, com socket Unix, `SO_PEERCRED`, operações tipadas, **política própria** e protocolo versionado com *handshake*.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Core sem root + executor com política** | Alta | Dois serviços leves | Boa | Baixo: falha na web não vira root arbitrário |
| B. Serviço único como root | Baixa | Um serviço | Boa | Alto: qualquer falha na web vira root |
| C. Core chamando comandos via `sudo` | Média | Alterar sudoers do cliente | Média | Alto: validação frágil de argumentos |

**Trade-offs.** A custa um protocolo interno e validação em dobro, em troca de conter o pior cenário (comprometimento do serviço web).

**Consequências.** Mais fácil: auditar o que roda como root. Mais difícil: versionar o protocolo e testar a política. Revisitar se surgirem operações que não caibam no modelo tipado.

**Ações.** [ ] Política com testes de tabela e *fuzzing*. [ ] Segundo revisor obrigatório em mudanças do executor.
