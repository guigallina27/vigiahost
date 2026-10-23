# ADR-006: Cliente nativo do clamd com FILDES

**Status:** Aceito · **Data:** 22/10/2026 (aceito com o início da Fase 0)

**Contexto.** O clamd costuma ser compartilhado com o e-mail; `clamdscan` não dá progresso, pausa nem vínculo exato ao objeto.

**Decisão.** Cliente próprio do protocolo (`VERSION`, `STATS`, `FILDES`, `INSTREAM`), com concorrência limitada; `clamscan` com limites maiores só para a fila de arquivos grandes.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Cliente nativo + FILDES** | Média | Nenhum | Boa | Baixo |
| B. `clamdscan` | Baixa | Nenhum | Média | Saída textual forjável; sem progresso |
| C. `clamscan` em cada execução | Baixa | Carrega as assinaturas a cada vez (memória e tempo) | Ruim | Sobrecarga em servidores pequenos |

**Consequências.** Mais fácil: progresso real, pausa e detecção ligada ao inode e hash; o clamd não precisa ler os arquivos. Mais difícil: manter o cliente do protocolo. Revisitar se o ClamAV mudar o protocolo.

**Ações.** [ ] Teste de integração com EICAR por `INSTREAM`. [ ] Leitura e exibição dos limites efetivos.
