# ADR-018: Arquivos entregues aos motores por descritor, nunca por nome

**Status:** Aceito · **Data:** 22/10/2026 (decidido com o corpus do E0.3, antes do adaptador dos motores da 1A)

**Contexto.** Os nomes de arquivo de uma conta de hospedagem são controlados por quem a comprometeu (modelo de ameaças, atacante 1). Na conferência do corpus sintético com os motores reais apareceram três problemas de entregar caminhos aos motores:

1. **Um nome derruba a varredura inteira.** O `yr scan -r` 1.21.0 entra em pânico (`cli/src/commands/scan.rs:927`, `unwrap()` em `None`) ao encontrar um nome que não é UTF-8 válido, e o processo termina sem analisar o restante do diretório. Um único arquivo com nome `\xff\xfe.php` esconderia a árvore inteira: é evasão, não só um defeito.
2. **Listas por linha não representam todos os nomes.** O `--scan-list` do `yr` e o `--file-list` do `clamscan` leem um caminho por linha; nomes com quebra de linha são legítimos no Linux e quebram a lista (e a saída em texto, que repete o nome).
3. **Troca entre o inventário e a análise.** Entre classificar um arquivo e o motor abri-lo pelo nome, ele pode virar um link para fora da conta.

**Decisão.** O inventário (E1.3) abre cada arquivo uma única vez, com `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` (e `O_NOATIME` como root), confere pelo `fstat` do descritor que é arquivo regular e entrega aos motores só o descritor:

| Motor | Entrega | Volta do resultado |
|---|---|---|
| YARA-X (`yr`) | Descritores herdados pelo processo filho (`ExtraFiles`), listados como `/dev/fd/N` no `--scan-list` pela entrada padrão; lotes de até 20.000 com `RLIMIT_NOFILE` elevado explicitamente | NDJSON com `path` = `/dev/fd/N`, mapeado de volta pelo índice do lote |
| ClamAV (clamd) | `FILDES` do protocolo nativo ([ADR-006](0006-cliente-nativo-clamd.md)) | Resposta por descritor |
| ClamAV (`clamscan`, fila de arquivos grandes) | Igual ao `yr`: `/dev/fd/N` no `--file-list` | Linha `/dev/fd/N: Nome FOUND` |

Nenhum motor percorre diretórios nem recebe nome de arquivo da conta. Abrir `/dev/fd/N` reabre o mesmo inode já conferido, não o caminho. O protótipo é [`test/corpus/gencorpus/verify.go`](../../test/corpus/gencorpus/verify.go), usado por `test/lab/check-corpus.sh`.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Descritor (`/dev/fd/N` e `FILDES`)** | Média | Descritores abertos por lote | Boa: 1 milhão de arquivos em 57,5 s no `yr` | Baixo; depende de `/dev/fd` (presente em todas as distribuições suportadas) |
| B. `--scan-list` com caminhos, pulando nomes problemáticos | Baixa | Nenhum | Boa | Arquivos com nome hostil ficam sem análise (evasão); corrida entre inventário e análise |
| C. `yr scan -r` por diretório | Baixa | Nenhum | Boa | Pânico com UTF-8 inválido aborta a árvore inteira; motor segue links e atravessa contas |
| D. Cópia ou link físico com nome seguro | Alta | Escrita em disco | Ruim | Links físicos não cruzam sistemas de arquivos; cópias dobram a E/S |

**Medições no laboratório** (WSL AlmaLinux 9, 16 vCPUs; `yr` 1.21.0, ClamAV 1.4.6):

| Corpus | Arquivos regulares | Tempo | Resultado |
|---|---|---|---|
| Controles positivos (EICAR, ZIP aninhado, marcador com nomes bidi, quebra de linha e acentos, 41 níveis, esparso de 512 MiB) | 14 | 11 s (`yr` + `clamscan`) | As 8 detecções YARA e as 3 do EICAR esperadas, nenhuma a mais |
| Sintético de 20 mil, com 13 entradas especiais (laços, links, FIFO, modo 000, nomes não UTF-8) | 20.006 | 248 s (`yr` + `clamscan`) | 20 marcadores achados; nenhum achado do ClamAV |
| Benigno (WordPress, WooCommerce, Joomla, Drupal, phpMyAdmin) | 47.692 | 493 s (`yr` + `clamscan`) | Nenhum falso positivo |
| Sintético de 1 milhão (4,1 GB, 144 mil diretórios) | 1.000.006 | 57,5 s (só `yr`) | 20 marcadores achados |

O `clamscan` usa uma thread (cerca de 80 arquivos por segundo aqui) e recarrega as assinaturas a cada execução: confirma o [ADR-006](0006-cliente-nativo-clamd.md), clamd com `FILDES` e concorrência para a varredura normal.

**Consequências.** Mais fácil: nome nenhum chega a um motor, então pânico por codificação, quebra de linha e corrida entre inventário e análise deixam de existir para o motor; o resultado fica ligado ao inode conferido. Mais difícil: o executor precisa de `LimitNOFILE` alto na unidade transitória do motor e de lotes; achados precisam guardar o caminho original do inventário (inclusive em hexadecimal quando não é UTF-8, como o manifesto do corpus). Revisitar se o `yr` passar a aceitar descritores ou a entrada padrão como alvo, ou se a biblioteca do YARA-X virar opção ([ADR-005](0005-yara-x-via-cli.md)).

**Ações.**
- [ ] Teste de integração do adaptador com o corpus sintético (nomes especiais) e com `ulimit -n` baixo (E1.4).
- [ ] Relatar o pânico do `yr scan -r` com nome não UTF-8 ao projeto YARA-X (ação externa; depende de autorização).
