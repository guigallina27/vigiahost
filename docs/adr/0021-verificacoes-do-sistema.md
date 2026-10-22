# ADR-021: Verificações do sistema como tipos de execução próprios

**Status:** Aceito · **Data:** 22/10/2026 (decidido na implementação de E2.2 e E2.4)

**Contexto.** A verificação contra os pacotes (E2.2) e as correções pendentes (E2.4) olham o sistema inteiro, não
caminhos escolhidos, e precisam de poderes diferentes dos da varredura: `rpm -Va` lê todos os arquivos dos pacotes; o
`dnf` grava trava e metadados em `/var/cache/dnf` mesmo no modo só cache; serviços com biblioteca substituída exigem
ler `/proc/PID/maps` de outros usuários. A busca por portas ocultas compara a tabela do kernel com `bind()` e só faz
sentido na rede do sistema, o que conflita com o `PrivateNetwork` da inspeção de processos. O banco tinha os tipos de
execução e de achado como lista fechada em `CHECK`, e a política de migração proíbe reconstruir tabelas que outras
migrações já alteraram.

**Decisão.**

1. Dois tipos novos, `integrity` e `updates`, cada um com subcomando e unidade transitória próprios no executor
   (`SpecFor` em `internal/executor/runs.go`). O core não manda caminho nem comando: o pedido só tem o tipo, e o
   executor recusa caminhos e contas nesses tipos. Protocolo 1.2.
2. Isolamento por tipo: `integrity` igual à varredura (sem rede, só leitura, `DAC_READ_SEARCH`/`DAC_OVERRIDE`);
   `updates` acrescenta `SYS_PTRACE` e escrita em `/var/cache/dnf` (quando existe). Atualizar a lista de pacotes
   (rede, escrita nas listas do APT/DNF, troca de usuário do APT) só acontece com `refresh_package_metadata: true` em
   `/etc/vigiahost/executor.json`, que o core não altera; desligado por padrão.
3. A inspeção de processos sai do `PrivateNetwork` para a rede do sistema com `IPAddressDeny=any` (nenhum tráfego IP,
   filtro BPF do cgroup), `AF_INET`/`AF_INET6` e `NET_BIND_SERVICE` só para testar portas abaixo de 1024 com `bind()`
   seguido de `close()`, sem `listen`. O teste só toca portas que não aparecem no `/proc/net` nem no netlink, e cada
   candidato é confirmado em duas rodadas com nova listagem (descarta efêmeros).
4. Achados do sistema (`kind = system`) têm um assunto estável (`security-updates`, `repo:<id>`, `tcp/31337`) que forma
   a identidade; diferença contra o pacote é identificada pelo caminho, não pelo hash. Numa execução completa desses
   tipos, achados abertos do mesmo motor que não aparecem mais são resolvidos com histórico (pacote reinstalado,
   correção aplicada). Ocultos nunca se resolvem sozinhos.
5. Migração 00009 afrouxa os `CHECK` de tipo para "letras minúsculas, até 32" editando o esquema
   (`writable_schema` + `RESET`, procedimento documentado pela SQLite para remover ou afrouxar `CHECK`); o tipo válido
   é conferido no Go (`report.ValidKind`). Relatórios (`integrity.json`, `updates.json`, `hidden.json`) ficam em
   `host_reports`, 30 por nome.

| Opção | Complexidade | Custo | Risco |
|---|---|---|---|
| **A. Tipos próprios com unidade e isolamento por tipo** | Média | Uma unidade por verificação | Mais combinações de isolamento para testar — coberto por teste com systemd real |
| B. Operações síncronas no socket do executor | Baixa | Nenhum | Processo root de longa duração rodando `rpm`/`dnf`; sem limite de cgroup nem cancelamento |
| C. Tudo dentro da inspeção de processos | Baixa | Inspeção mais lenta | Mistura poderes (cache do dnf, rede) numa unidade que roda com frequência |

| Opção para o `CHECK` | Risco |
|---|---|
| **Edição do esquema (`writable_schema`)** | Precisa de `RESET` para a conexão única recarregar; coberto por teste de migração |
| Reconstrução das tabelas (12 passos) | Apaga colunas criadas por migrações paralelas (00006 a 00008) ao copiar uma lista fixa |
| Tabelas novas por tipo | Duplica fila, agendamento e achados |

**Consequências.** Mais fácil: novos tipos (AIDE, Chkrootkit) entram sem migração de `CHECK`; o `pkgverify` serve de
base para a triagem deles. Mais difícil: a inspeção de processos passa a depender do filtro BPF do cgroup para manter
"sem tráfego"; em kernel sem suporte o systemd avisa e segue, e a unidade ainda não abre conexões (o inspetor não
conecta a nada). Revisitar quando a inspeção ganhar coleta remota.
