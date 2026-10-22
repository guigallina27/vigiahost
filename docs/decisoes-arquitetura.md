# Decisões de arquitetura (ADRs)

> **VigiaHost · 22/10/2026 · Todos com status "Proposto"**, até a aprovação do [escopo v2.3](escopo-v2.md). Projeto sob GPL-3.0. Responsáveis pela aprovação: responsável técnico e responsável pelo produto (a definir).
> Na Fase 0, cada ADR vira um arquivo em `docs/adr/` no repositório do produto. Critérios das tabelas: complexidade de implementação, custo de operação no servidor do cliente, escala e risco.

| ADR | Decisão | Seção do escopo |
|---|---|---|
| 001 | Go + React embarcado; central sem Next.js | 6.3, 18 |
| 002 | Separação core/executor com política no executor | 6.1, 13 |
| 003 | SQLite com fila própria e agendador orientado ao banco | 6.3, 12, 17 |
| 004 | Execuções em unidades systemd transitórias | 6.1, 12 |
| 005 | YARA-X como motor principal via CLI | 7.2 |
| 006 | Cliente nativo do clamd com FILDES | 7.2 |
| 007 | Inventário único e cache por inode, `ctime` e versão | 6.2, 12.1 |
| 008 | Objetos, achados, cobertura e ciclo de vida do achado | 10 |
| 009 | Repositórios assinados; TUF para tarball e central | 15 |
| 010 | Fontes de regras e licenças | 7.3 |
| 011 | Contas do servidor como unidade de escopo | 9.1 |
| 012 | Perfis de recursos com travas no executor | 12 |
| 013 | Integrações complementares opcionais como entrada não confiável | 7.5, 13 |

---

## ADR-001: Go + React embarcado; central sem Next.js

**Status:** Proposto · **Data:** 22/10/2026

**Contexto.** O produto é instalado por um comando em servidores de clientes, de EL8 a Ubuntu 26.04, e precisa de consumo baixo em repouso. A interface é rica (tabelas grandes, tempo real). A central virá depois e deve reaproveitar a interface.

**Decisão.** Binário Go estático (`CGO_ENABLED=0`) com a interface React (Vite) embarcada. A central usa Go + PostgreSQL e os mesmos pacotes React.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Go + React embarcado** | Média | Baixo: um binário, sem Node | Boa para o painel local | Baixo |
| B. Go (API) + Next.js | Alta | Node em produção em cada servidor | Boa | Duas pilhas de interface |
| C. Backend em Python ou Node | Média | Interpretador e dependências no servidor; mais memória | Média | Dependência das versões da distribuição |

**Trade-offs.** A perde renderização no servidor, que não é necessária num painel autenticado; ganha implantação simples e uma única pilha de interface.

**Consequências.** Mais fácil: instalar, atualizar e auditar um binário; compartilhar componentes com a central. Mais difícil: o CI mantém duas cadeias de build (Go e pnpm). Revisitar se a central exigir renderização no servidor.

**Ações.** [ ] Monorepo com pacote de componentes compartilhado. [ ] Recursos embarcados com hash no nome e cache imutável.

---

## ADR-002: Separação core/executor com política no executor

**Status:** Proposto · **Data:** 22/10/2026

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

---

## ADR-003: SQLite com fila própria e agendador orientado ao banco

**Status:** Proposto · **Data:** 22/10/2026

**Contexto.** Agendamentos e execuções precisam sobreviver a reinícios sem duplicar; o produto não deve exigir outro serviço de banco no servidor do cliente.

**Decisão.** SQLite (WAL, um escritor, `STRICT`, FTS5) com tabela de jobs (*lease*, *heartbeat*, idempotência, máquina de estados) e agendador com `next_run_at` persistido e chave única `(agendamento, horário previsto)`. goqite como referência.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. SQLite + fila e agendador próprios** | Média | Nenhum serviço extra | 1 milhão de arquivos com inventário fora do banco | Baixo |
| B. gocron em memória + SQLite | Baixa | Nenhum | Boa | Horários perdidos e duplicidade após reinício |
| C. PostgreSQL local | Média | Serviço extra em cada servidor | Alta | Operação e conflito com bancos do cliente |

**Trade-offs.** A aceita um único escritor (gravações agrupadas) para não depender de outro serviço.

**Consequências.** Mais fácil: backup com `VACUUM INTO`, instalação simples. Mais difícil: concorrência de escrita exige disciplina. Revisitar na central (PostgreSQL, ADR-001).

**Ações.** [ ] Testes de recuperação com `kill -9` e salto de relógio (`testing/synctest`).

---

## ADR-004: Execuções em unidades systemd transitórias

**Status:** Proposto · **Data:** 22/10/2026

**Contexto.** Varreduras não podem travar o servidor e precisam de pausa, cancelamento e recuperação após reinício do executor.

**Decisão.** Cada execução roda em unidade transitória criada via D-Bus (`coreos/go-systemd`), com nome determinístico, limites de cgroup, sem rede e somente leitura.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Unidades transitórias** | Média | Nenhum | Boa | Baixo; EL8 (cgroup v1) com funções limitadas |
| B. Processos filhos com `nice`/`ionice`/`setrlimit` | Baixa | Nenhum | Média | Sem limite de memória do grupo nem pausa confiável |
| C. Contêineres (podman) | Alta | Runtime de contêiner | Boa | Dependência pesada e incomum em hospedagem |

**Trade-offs.** A depende de systemd (premissa do produto) e de cgroup v2 para pausa e `io.max`.

**Consequências.** Mais fácil: cancelar a árvore inteira, ajustar limites em tempo real, reconciliar pelo nome. Mais difícil: testar nas variações de versão do systemd. Revisitar se houver demanda por sistemas sem systemd.

**Ações.** [ ] Matriz de capacidades detectadas (seção 5.3 do escopo) exibida na interface.

---

## ADR-005: YARA-X como motor principal via CLI

**Status:** Proposto · **Data:** 22/10/2026

**Contexto.** As distribuições trazem YARA de 4.1.3 a 4.5.5; o YARA original está só em manutenção.

**Decisão.** Distribuir o `yr` (YARA-X) em pacote próprio; regras pré-compiladas, saída NDJSON, `--cpu-limit` e limite de tempo. YARA 4.x apenas para memória de processos (Fase 3).

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. YARA-X via CLI distribuída** | Média | Um binário | Boa | Incompatibilidades de regras tratadas na compilação |
| B. YARA 4.x da distribuição | Baixa | Nenhum | Média | Comportamento diferente por distribuição |
| C. Biblioteca Go do YARA-X | Alta | Nenhum | Boa | Exige cgo e biblioteca C; quebra o binário estático |

**Consequências.** Mais fácil: comportamento igual em todas as distribuições. Mais difícil: acompanhar releases do YARA-X e traduzir regras antigas. Revisitar quando o YARA-X suportar varredura de processos.

**Ações.** [ ] *Golden files* por versão do `yr`. [ ] Medição de desempenho por regra.

---

## ADR-006: Cliente nativo do clamd com FILDES

**Status:** Proposto · **Data:** 22/10/2026

**Contexto.** O clamd costuma ser compartilhado com o e-mail; `clamdscan` não dá progresso, pausa nem vínculo exato ao objeto.

**Decisão.** Cliente próprio do protocolo (`VERSION`, `STATS`, `FILDES`, `INSTREAM`), com concorrência limitada; `clamscan` com limites maiores só para a fila de arquivos grandes.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Cliente nativo + FILDES** | Média | Nenhum | Boa | Baixo |
| B. `clamdscan` | Baixa | Nenhum | Média | Saída textual forjável; sem progresso |
| C. `clamscan` em cada execução | Baixa | Carrega as assinaturas a cada vez (memória e tempo) | Ruim | Sobrecarga em servidores pequenos |

**Consequências.** Mais fácil: progresso real, pausa e detecção ligada ao inode e hash; o clamd não precisa ler os arquivos. Mais difícil: manter o cliente do protocolo. Revisitar se o ClamAV mudar o protocolo.

**Ações.** [ ] Teste de integração com EICAR por `INSTREAM`. [ ] Leitura e exibição dos limites efetivos.

---

## ADR-007: Inventário único e cache por inode, `ctime` e versão

**Status:** Proposto · **Data:** 22/10/2026

**Contexto.** Cada ferramenta percorria o disco separadamente; não havia progresso real nem cobertura comparável.

**Decisão.** Um percurso por execução, classificação por conteúdo, distribuição do mesmo descritor aos motores e cache com chave `(dispositivo, inode, tamanho, mtime, ctime)` + versão de assinaturas/regras.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Inventário único + cache** | Alta | I/O reduzido | Boa | Corridas e arquivos especiais exigem cuidado |
| B. Cada ferramenta percorre o disco | Baixa | I/O multiplicado | Ruim | Sem cobertura comparável |
| C. Só monitoramento em tempo real | Alta | Agente residente | Boa | Não cobre o estado inicial; fica como complemento na Fase 3 |

**Consequências.** Mais fácil: rotina incremental, deduplicação, ordem por risco. Mais difícil: regras de invalidação do cache. Revisitar com o monitoramento contínuo.

**Ações.** [ ] Testes de FIFO, socket, FUSE e troca de arquivo durante a leitura.

---

## ADR-008: Objetos, achados, cobertura e ciclo de vida do achado

**Status:** Proposto · **Data:** 22/10/2026

**Contexto.** Seis cópias do mesmo minerador viravam "seis malwares"; um estado único misturava falha, execução parcial e detecção.

**Decisão.** Objeto (SHA-256) com várias localizações; achados por motor e fonte de assinatura; execução avaliada em três dimensões (estado, achados, cobertura); ciclo de vida do achado separado da severidade.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Modelo de objetos e três dimensões** | Média | Nenhum | Boa | Baixo |
| B. Estado único por execução (v1) | Baixa | Nenhum | Boa | Esconde cobertura parcial |
| C. Relatórios brutos por ferramenta | Baixa | Nenhum | Ruim | Duplicidade e falsa confirmação |

**Consequências.** Mais fácil: cobertura honesta e contagem correta. Mais difícil: esquema e interface mais ricos. Revisitar quando a central consolidar vários servidores.

**Ações.** [ ] Glossário e componentes `SeverityBadge`/`StatusBadge` alinhados ao modelo.

---

## ADR-009: Repositórios assinados; TUF para tarball e central

**Status:** Proposto · **Data:** 22/10/2026

**Contexto.** Atualizações precisam ser seguras e nativas para o administrador.

**Decisão.** Repositórios APT e DNF assinados como canal principal (estável e beta); script de bootstrap só adiciona o repositório; go-tuf v2 para autoatualização por tarball e para a central. **Em 22/10/2026 decidiu-se distribuir somente pelo GitHub por enquanto**: Releases públicos do repositório `guigallina27/vigiahost` (pré-lançamento até a 1.0) e, a partir do beta externo, GitHub Pages do mesmo repositório; domínio próprio antes do beta. Chave raiz GPG offline em dois tokens de hardware com dois responsáveis; subchave anual e chave do cosign no *environment* `release` do CI, com aprovação manual.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Repositórios assinados + TUF** | Média | Nenhum | Boa | Custódia de chaves |
| B. Script que baixa binários e se atualiza | Baixa | Nenhum | Média | Atualização fora do gerenciador; ataques de rollback |
| C. Somente tarball com TUF | Média | Nenhum | Boa | Experiência estranha ao administrador |

**Consequências.** Mais fácil: atualização com as ferramentas do sistema; começar sem domínio nem CDN. Mais difícil: manter repositórios e rotação de chaves; respeitar os limites do Pages (1 GB publicado, banda de referência de 100 GB/mês); migrar a origem dos servidores quando houver domínio (o pacote reescreve o arquivo de origem). Revisitar antes do beta externo (domínio e CDN) e se surgir distribuição sem APT/DNF.

**Ações.** [ ] Cerimônia da chave raiz (épico E0.7). [ ] Atestados de proveniência do GitHub e SBOM assinado com a chave própria do cosign. [ ] Testes de atualização, retorno e troca de origem em VM.

---

## ADR-010: Fontes de regras e licenças

**Status:** Proposto · **Data:** 22/10/2026

**Contexto.** Regras de terceiros têm licenças diversas (DRL 1.1, ELv2) e podem ser lentas ou maliciosas.

**Decisão.** Não embarcar regras de terceiros; baixar no servidor as fontes habilitadas, fixar versão, verificar hash, compilar e testar em unidade isolada e promover com controle positivo e corpus benigno; exibir autor, fonte, licença e link em cada achado.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Baixar, verificar e promover no cliente** | Média | Download periódico | Boa | Baixo |
| B. Embarcar regras de terceiros | Baixa | Nenhum | Boa | Violação de licença |
| C. Só regras próprias | Baixa | Nenhum | Ruim | Detecção pobre |

**Consequências.** Mais fácil: conformidade e retorno de conjunto. Mais difícil: o servidor precisa de acesso à fonte. Revisitar após a revisão jurídica da ELv2.

**Ações.** [ ] Revisão jurídica das licenças. [ ] Fluxo de promoção com troca atômica.

---

## ADR-011: Contas do servidor como unidade de escopo

**Status:** Proposto · **Data:** 22/10/2026

**Contexto.** Hospedagem é administrada por conta; o modelo do Imunify (lista de contas, verificação por conta) é o esperado pelos operadores.

**Decisão.** Contas derivadas do sistema (`getent passwd`, `UID_MIN`, diretório pessoal) desde a Fase 1B, enriquecidas pelos painéis na Fase 3. Agregação pelo UID e pelo caminho já registrados, sem nova leitura do disco. Conta como unidade de paralelismo e prioridade.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Sistema + enriquecimento por painel** | Média | Nenhum | Boa | Atribuição por UID ou caminho pode divergir em casos raros |
| B. Só pelo painel | Média | Nenhum | Boa | Sem contas em servidores sem painel |
| C. Só caminhos, sem conceito de conta | Baixa | Nenhum | Ruim | Investigação e priorização lentas |

**Consequências.** Mais fácil: verificar e priorizar por conta. Mais difícil: autorização por conta quando houver acesso de revendedores e clientes. Revisitar com a decisão sobre multiempresa.

**Ações.** [ ] Testes de escopo por conta e de isolamento entre contas.

---

## ADR-012: Perfis de recursos com travas no executor

**Status:** Proposto · **Data:** 22/10/2026

**Contexto.** Servidores pequenos precisam de proteção contra sobrecarga; servidores grandes precisam liberar recursos.

**Decisão.** Perfis Leve, Padrão, Intensivo e próprios, aplicados como propriedades de cgroup; sugestão pelo hardware; ajuste em tempo real. O executor impõe reserva mínima para o sistema e exige confirmação explícita, reautenticação e auditoria para ultrapassá-la.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Perfis + travas no executor** | Média | Nenhum | Boa | Baixo |
| B. Limites fixos no código | Baixa | Nenhum | Ruim em servidores grandes | Lento demais ou pesado demais |
| C. Limites livres sem travas | Baixa | Nenhum | Boa | Configuração errada derruba o servidor |

**Consequências.** Mais fácil: adaptar a cada servidor. Mais difícil: explicar os efeitos na interface. Revisitar com o histórico real de execuções.

**Ações.** [ ] Teste: pedido acima de 75% da RAM sem confirmação é recusado.

---

## ADR-013: Integrações complementares opcionais como entrada não confiável

**Status:** Proposto · **Data:** 22/10/2026

**Contexto.** OSV-Scanner, Wordfence Intelligence, abuse.ch e Falco ampliam a visão (vulnerabilidades e comportamento), mas trazem dados e termos de terceiros.

**Decisão.** Todas opcionais; bases baixadas por unidade separada com rede, verificadas e versionadas; consultas locais; chaves como segredos; dados e eventos tratados como entrada não confiável. Falco desligado por padrão, como serviço próprio fora do executor.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Opcionais, locais e não confiáveis** | Média | Só o que for ativado | Boa | Baixo |
| B. Todas ativas por padrão | Média | Alto (Falco residente, downloads) | Média | Termos de uso e consumo |
| C. Delegar a agentes externos (osquery, Wazuh) | Baixa | Outro agente residente | Boa | Sobreposição e dependência externa |

**Consequências.** Mais fácil: o núcleo funciona sem terceiros. Mais difícil: manter adaptadores e acompanhar termos. Revisitar a cada mudança de termos dos feeds.

**Ações.** [ ] Registro de termos e atribuições por fonte. [ ] *Fuzzing* dos interpretadores de feeds e eventos.
