# Decisões de arquitetura (ADRs)

> **VigiaHost · Projeto sob GPL-3.0.** Cada decisão fica em um arquivo em [`adr/`](adr/), no formato: contexto, decisão, opções consideradas (complexidade, custo no servidor do cliente, escala e risco), trade-offs, consequências e ações.
> ADRs 001 a 013 vieram do [escopo v2.3](escopo-v2.md) e foram aceitos com o início da Fase 0 em 22/10/2026; 014 e 015 foram decididos na implementação. Uma decisão nova ou revista vira um ADR novo, que substitui o anterior.

| ADR | Decisão | Seção do escopo |
|---|---|---|
| [001](adr/0001-go-e-react-embarcado.md) | Go + React embarcado; central sem Next.js | 6.3, 18 |
| [002](adr/0002-separacao-core-executor.md) | Separação core/executor com política no executor | 6.1, 13 |
| [003](adr/0003-sqlite-fila-e-agendador.md) | SQLite com fila própria e agendador orientado ao banco | 6.3, 12, 17 |
| [004](adr/0004-unidades-systemd-transitorias.md) | Execuções em unidades systemd transitórias | 6.1, 12 |
| [005](adr/0005-yara-x-via-cli.md) | YARA-X como motor principal via CLI | 7.2 |
| [006](adr/0006-cliente-nativo-clamd.md) | Cliente nativo do clamd com FILDES | 7.2 |
| [007](adr/0007-inventario-unico-e-cache.md) | Inventário único e cache por inode, `ctime` e versão | 6.2, 12.1 |
| [008](adr/0008-objetos-achados-e-cobertura.md) | Objetos, achados, cobertura e ciclo de vida do achado | 10 |
| [009](adr/0009-distribuicao-e-chaves.md) | Repositórios assinados; TUF para tarball e central | 15 |
| [010](adr/0010-fontes-de-regras-e-licencas.md) | Fontes de regras e licenças | 7.3 |
| [011](adr/0011-contas-como-escopo.md) | Contas do servidor como unidade de escopo | 9.1 |
| [012](adr/0012-perfis-de-recursos.md) | Perfis de recursos com travas no executor | 12 |
| [013](adr/0013-integracoes-complementares.md) | Integrações complementares opcionais como entrada não confiável | 7.5, 13 |
| [014](adr/0014-protocolo-core-executor.md) | Protocolo core–executor em JSON por linha sobre socket Unix | 6.1, 13 |
| [015](adr/0015-instalacao-sem-iniciar-servicos.md) | A instalação do pacote não habilita nem inicia os serviços | 15 |
