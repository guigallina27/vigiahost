# Modelo de ameaças — VigiaHost

> **Versão 0.1 · 22/10/2026 · Fase 0.** Revisado ao fim de cada fase (plano de implementação, seção 4). Complementa o [escopo](escopo-v2.md), seção 13.
> Situação: **implementado** (existe no código e tem teste), **planejado** (fase indicada).

## 1. Ativos

| Ativo | Por que importa |
|---|---|
| Privilégio root do executor | Quem o controla controla o servidor inteiro |
| Arquivos e processos das contas de hospedagem | Dados de clientes; alvo de alteração e de exfiltração |
| Banco local (achados, exceções, auditoria) | Exceção indevida esconde malware; auditoria apagada esconde o ataque |
| Chaves de assinatura de pacotes | Comprometem todas as instalações de uma vez |
| Credenciais do painel e segredos de integrações | Acesso ao produto e a serviços externos |

## 2. Atacantes considerados

1. **Conta de hospedagem comprometida**: controla nomes e conteúdo de arquivos, processos e cron do próprio usuário.
2. **Serviço web comprometido**: execução de código como o usuário `vigiahost`.
3. **Usuário local sem privilégios**: qualquer outra conta do servidor.
4. **Atacante com root**: pode adulterar tudo localmente; o produto só consegue dificultar e evidenciar.
5. **Cadeia de suprimentos**: dependências, *actions* do CI, regras e feeds de terceiros, pipeline de release.

## 3. Limites de confiança e ameaças (STRIDE)

### 3.1 Navegador → core (HTTP)

| Ameaça | Controle | Situação |
|---|---|---|
| Falsificação de requisição entre sites | `http.CrossOriginProtection`; cookies `SameSite=Strict` | Implementado (proteção de origem); cookies na 1A |
| XSS por nome de arquivo malicioso | CSP `default-src 'self'` sem `inline` nem `data:` (a interface não tem script nem estilo embutido no HTML); React escapa todo texto; nada usa `dangerouslySetInnerHTML` | Implementado |
| Nome de arquivo que engana o operador (bidi, quebra de linha, invisíveis) | `PathText` mostra controles e marcas de direção como escapes destacados e avisa o leitor de tela | Implementado (E0.6) |
| Clickjacking | `frame-ancestors 'none'` | Implementado |
| Exposição da interface na rede | Escuta em `127.0.0.1` por padrão; aviso no log se não for local | Implementado |
| Força bruta de login | Bloqueio progressivo, registro para fail2ban/LFD | Planejado (1A) |
| Conexões lentas prendendo o serviço | Limites de tempo e de cabeçalho no `http.Server` | Implementado |

### 3.2 Core → executor (socket Unix)

| Ameaça | Controle | Situação |
|---|---|---|
| Processo qualquer falando com o executor | Socket `0660 root:vigiahost` | Implementado e testado |
| Usuário incluído no grupo indevidamente | Política por UID via `SO_PEERCRED`, recusa registrada no journal | Implementado e testado |
| Core comprometido pedindo operação arbitrária | Só operações tipadas registradas; desconhecidas recusadas | Implementado e testado |
| Mensagem gigante ou malformada | Limite de 2 MiB por pedido lido pelo executor (as respostas, lidas pelo core, vão até 16 MiB), conexão encerrada, *fuzzing* do decodificador | Implementado e testado |
| Versões incompatíveis após atualização parcial | *Handshake* com versão do protocolo | Implementado e testado |
| Vazamento de detalhes internos ao core | Erro interno sem detalhes; detalhes só no journal | Implementado e testado |
| Caminhos fora do escopo nas operações | Política de caminhos com `openat2`/`os.Root` no executor | Planejado (1A) |
| Excesso de conexões | Limite de conexões simultâneas e de inatividade | Implementado |

### 3.3 Executor → sistema e motores

| Ameaça | Controle | Situação |
|---|---|---|
| Executor com poderes demais | `CapabilityBoundingSet` mínimo por fase, `ProtectSystem`, filtro de chamadas de sistema; exposição 2,4 no `systemd-analyze security` | Implementado (Fase 0) |
| Arquivo malicioso explorando o processo root | Motores sempre em processos externos, em unidades transitórias sem rede e só leitura | Planejado (1A) |
| Saída de scanner forjada por nome de arquivo | Formatos estruturados (FILDES, NDJSON, JSON); *fuzzing* dos interpretadores | Planejado (1A) |
| Nome hostil que derruba ou desvia o motor (o `yr scan -r` 1.21.0 aborta a árvore inteira com nome não UTF-8; quebra de linha corrompe listas; troca por link entre inventário e análise) | Motores nunca percorrem diretórios nem recebem nomes: o inventário abre com `O_NOFOLLOW`, confere o tipo pelo descritor e entrega `/dev/fd/N` ou `FILDES` ([ADR-018](adr/0018-arquivos-aos-motores-por-descritor.md)); corpus sintético com nomes especiais conferido nos motores reais | Protótipo validado (Fase 0); adaptador na 1A |
| Corrida de link simbólico ou físico na quarentena | Descritor aberto, `O_NOFOLLOW`, `nlink == 1`, identidade conferida | Planejado (2) |

### 3.4 Dados de terceiros (regras, feeds, eventos)

| Ameaça | Controle | Situação |
|---|---|---|
| Regra YARA lenta ou maliciosa | Compilação e teste em unidade isolada, limite de tempo, promoção com corpus | Planejado (1A/2) |
| Feed adulterado ou fora do ar | Origem verificada, versão fixada, produto funciona sem o feed | Planejado (3) |

### 3.5 Cadeia de suprimentos e distribuição

| Ameaça | Controle | Situação |
|---|---|---|
| *Action* do CI comprometida | Fixadas por SHA de commit; `persist-credentials: false`; permissões mínimas | Implementado |
| Dependência maliciosa recém-publicada | Dependabot com espera mínima de 7 dias (Go, npm e *actions*); versões exatas; na interface, pnpm com `minimumReleaseAge` de 7 dias e lockfile obrigatório (`--frozen-lockfile`) | Implementado |
| Script de instalação malicioso em pacote npm | pnpm com `strictDepBuilds`: nenhum pacote roda script de instalação sem aprovação explícita | Implementado |
| Dependência com vulnerabilidade conhecida | `govulncheck` no CI; revisão de dependências nos PRs | Implementado |
| Licença incompatível | Verificação de licenças compatíveis com GPL-3.0 no CI (go-licenses para o Go; `web/scripts/licenses.mjs` para a interface, que também gera os avisos de terceiros embarcados) | Implementado |
| Segredo commitado | Varredura de segredos (gitleaks) no CI | Implementado |
| PR de *fork* executando código no laboratório | Testes em VM só em eventos confiáveis | Planejado (com os *runners* próprios) |
| Chave de assinatura vazada | Raiz offline em dois tokens; subchave anual; aprovação manual no *environment* `release` | Planejado (E0.7, aguarda tokens) |
| Pacote adulterado no caminho | Pacotes e `SHA256SUMS` assinados; cosign; proveniência | Planejado (E0.2, aguarda chaves) |

### 3.6 Pacote e instalação

| Ameaça | Controle | Situação |
|---|---|---|
| Serviço no ar antes da revisão | Instalação não inicia serviços (ADR-015) | Implementado e testado |
| Atualização derrubando outros serviços | `try-restart` só nos serviços do produto | Implementado e testado |
| Perda de dados na remoção | Dados preservados; só o *purge* apaga | Implementado e testado |
| Banco incompatível após retorno de versão | Migrações expandir/contrair; binário antigo segue sem migrar | Implementado e testado |

## 4. Riscos aceitos na Fase 0

- **Interface sem TLS**: escuta só em `127.0.0.1` (acesso por túnel SSH) até o certificado da 1A.
- **Sem autenticação**: a única rota é a de saúde, sem dados sensíveis; login e MFA entram na 1A, antes de qualquer dado de varredura.
- **Pacotes de teste sem assinatura de release**: a cerimônia de chaves depende dos tokens; nenhum pacote é publicado até lá.
- **Root local**: fora do alcance de qualquer controle local; mitigação parcial com auditoria encadeada e ancoragem remota (planejado).
