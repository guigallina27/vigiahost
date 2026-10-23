# Glossário

Um termo por conceito, igual na interface, na API e na documentação ([escopo, seção 14.2](escopo-v2.md)). Termos técnicos sem tradução consagrada ficam no original.

| Termo | Definição | Não usar |
|---|---|---|
| **Achado** | Indício encontrado por um motor sobre um objeto ou processo, com severidade e estado | "alerta", "ameaça" (quando ainda não confirmado) |
| **Objeto** | Conteúdo identificado pelo SHA-256; o mesmo objeto pode ter várias localizações | "arquivo" (quando se fala do conteúdo) |
| **Localização** | Onde um objeto está: caminho, dispositivo, inode, dono e datas | — |
| **Cobertura** | Quanto do que era elegível foi de fato analisado, por motor, com os motivos do que ficou de fora | "progresso" |
| **Motor** | Ferramenta que analisa objetos ou o sistema (ClamAV, YARA-X, LMD, AIDE etc.) | "scanner" na interface |
| **Fonte de regra** | Origem de uma assinatura ou regra (ex.: YARA Forge), com versão e licença | — |
| **Execução** | Uma rodada de verificação, avaliada em três dimensões: estado, achados e cobertura | "scan", "job" na interface |
| **Exceção** | Decisão registrada de ignorar um achado, de preferência pelo hash, com motivo e validade | "whitelist" |
| **Quarentena** | Objeto retirado do lugar, cifrado e guardado com metadados para restauração | "apagar" |
| **Referência do AIDE** | Banco de integridade aprovado contra o qual as diferenças são comparadas | "baseline" na interface |
| **Conta** | Usuário do sistema ou da hospedagem dono de arquivos e processos | "usuário" (reservado ao painel) |
| **Usuário** | Pessoa com acesso ao painel do VigiaHost | "conta" |

## Escalas e estados

| Conceito | Valores |
|---|---|
| Severidade | Crítico, Alto, Médio, Baixo, Informativo |
| Estado do achado | Novo, Em análise, Confirmado, Resolvido, Falso positivo, Coberto por exceção |
| Estado da execução | Na fila, Em execução, Concluída, Parcial, Falha, Falha de motor, Cancelada, Interrompida e recuperada |
| Saúde do motor | Operacional, Degradado, Indisponível |
| Atualização do motor | Em dia, Atrasada |
