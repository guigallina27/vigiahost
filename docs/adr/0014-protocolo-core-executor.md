# ADR-014: Protocolo core–executor em JSON por linha sobre socket Unix

**Status:** Aceito · **Data:** 22/10/2026 (decidido na implementação da Fase 0)

**Contexto.** O ADR-002 separou o core sem privilégios do executor root, mas não definiu o formato da conversa entre eles. O executor deve assumir que o core pode estar comprometido, então o protocolo precisa ser pequeno, fácil de auditar e de submeter a *fuzzing*.

**Decisão.** Mensagens JSON, uma por linha, com no máximo 64 KiB, em socket Unix `0660 root:vigiahost`. A identidade do cliente vem do kernel (`SO_PEERCRED`), nunca da mensagem. A primeira mensagem é obrigatoriamente `hello`, com a versão do protocolo (`major.minor`); versões principais diferentes encerram a conexão. Só operações tipadas e registradas são aceitas; operação desconhecida é recusada e registrada. Erros internos chegam ao core sem detalhes; os detalhes ficam no journal.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. JSON por linha, só biblioteca padrão** | Baixa | Nenhum | Suficiente: chamadas de controle, não de dados em volume | Baixo; *fuzzing* simples |
| B. gRPC/ConnectRPC com protobuf | Média | Dependências maiores no binário root | Alta | Mais código no processo privilegiado |
| C. D-Bus próprio | Alta | Política do D-Bus em cada distribuição | Média | Configuração espalhada pelo sistema |

**Trade-offs.** A dispensa geração de código e mantém o executor só com a biblioteca padrão; perde-se a tipagem forte do protobuf, compensada por estruturas Go compartilhadas no pacote `ipc` e testes de contrato.

**Consequências.** Mais fácil: auditar, testar com `net.Pipe` e *fuzzing*, depurar com ferramentas de texto. Mais difícil: transferir grandes volumes (inventário e resultados) — esses dados trafegam por arquivos no diretório de saída da execução, não pelo socket. Revisitar se o volume de chamadas crescer a ponto de o JSON pesar.

**Ações.** [x] Limite de tamanho, *handshake* e recusa de operação desconhecida com testes. [x] Teste com socket real e `SO_PEERCRED` no Linux. [x] *Fuzzing* do decodificador no CI. [ ] Teste de contrato entre versões N-1 e N do core e do executor.
