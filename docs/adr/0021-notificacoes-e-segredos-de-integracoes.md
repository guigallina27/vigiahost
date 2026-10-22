# ADR-021: Notificações com caixa de saída no banco, webhook no padrão Standard Webhooks e segredos cifrados

**Status:** Aceito · **Data:** 22/10/2026 (decidido na implementação do E1.12)

**Contexto.** O E1.12 pede e-mail e webhook assinado com caixa de saída, deduplicação e botão de teste (escopo,
seção 16). Quatro decisões precisavam de resposta: onde o envio roda e como sobrevive a reinícios e a destinos fora do
ar; como o receptor confere que a mensagem veio do servidor e não foi repetida; como evitar que o webhook vire um
proxy para a rede interna (SSRF); e onde guardar a senha SMTP e o segredo do webhook, que o escopo (seção 13) manda
cifrar em repouso com a chave fora do banco.

**Decisão.**

1. **Envio no core, com caixa de saída no SQLite.** Os produtores (orquestrador, vigia do executor, cópia diária do
   banco) chamam `notify.Service.Emit`, que aplica as regras e só grava na tabela `notification_outbox` — nenhuma
   rede no caminho da fila de execuções. Um laço próprio do core reserva as mensagens vencidas (a tentativa conta
   na reserva; se o core cair no meio, a mensagem volta depois de 5 minutos), envia com tempo limite de 20 s por
   mensagem, um canal em paralelo ao outro, e aplica recuo exponencial (30 s dobrando até 1 h, com até 10% de
   variação) até 8 tentativas; depois disso, ou em recusa definitiva (SMTP 5xx, HTTP 4xx exceto 408/425/429,
   destino recusado pela política, configuração inválida), a mensagem fica em `failed` e o painel permite reenviar.
2. **Deduplicação e agrupamento.** Cada evento tem uma chave (achado, execução, motor, executor, cópia do banco) e
   cada regra uma janela (`dedup_minutes`); a mesma chave não entra de novo no mesmo canal dentro da janela
   (`notification_dedup`). Achados novos esperam 60 s: os que chegam nesse intervalo entram na mesma mensagem
   enquanto ela não foi tentada (amostra de 25 itens, contagem total e por severidade). 500 achados de uma
   varredura viram um resumo, não 500 e-mails.
3. **Webhook no padrão [Standard Webhooks](https://www.standardwebhooks.com/).** POST JSON com `webhook-id`
   (estável entre tentativas), `webhook-timestamp` (segundos Unix) e `webhook-signature: v1,<base64 do
   HMAC-SHA256(chave, id.timestamp.corpo)>`. O receptor confere a assinatura em tempo constante, recusa carimbo fora
   de 5 minutos e descarta `webhook-id` repetido. Formato e exemplos de verificação em
   [notificacoes.md](../notificacoes.md). O segredo é do administrador (pode ser gerado no navegador pela tela);
   a API nunca o devolve.
4. **Política de rede do webhook.** Só `http`/`https`, sem usuário e senha no endereço, sem seguir redirecionamento
   e sem proxy do ambiente. O IP é conferido no momento do `connect` (controle do `net.Dialer`), para todos os
   endereços que o nome resolver — vale contra troca de DNS entre a validação e o envio. Link-local
   (169.254.0.0/16, fe80::/10) e metadados de nuvem (100.100.100.200, fd00:ec2::254) são sempre recusados; rede
   privada e loopback só com `allow_private_network`, marcado pelo administrador no canal. O SMTP aceita rede
   privada (relés internos são comuns), mas também recusa link-local e metadados.
5. **SMTP.** `starttls` exige o STARTTLS anunciado (sem queda para texto puro); `tls` é TLS desde a conexão;
   `none` só vale para relé no próprio servidor (localhost). Certificado sempre verificado com as raízes do sistema;
   autenticação PLAIN só sobre TLS ou no relé local.
6. **Segredos cifrados com AES-256-GCM** (pacote `internal/secrets`), com dado adicional autenticado pelo tipo de
   canal. A chave de 32 bytes vem de `$CREDENTIALS_DIRECTORY/vigiahost-secrets-key` quando o administrador configura
   `LoadCredential=` na unidade; senão, do arquivo `secrets.key` (0600) no diretório de estado, criado no primeiro
   início. A API só diz `secret_configured` e `secret_readable`; auditoria e logs nunca levam o valor.

| Opção | Complexidade | Custo no servidor | Risco |
|---|---|---|---|
| **A. Caixa de saída no SQLite, envio no core** | Média | Uma goroutine; uma linha por mensagem | Envio compartilha o processo do painel — mitigado por tempo limite e paralelismo por canal |
| B. Envio síncrono no orquestrador | Baixa | Nenhum | Destino lento trava a fila; sem nova tentativa após reinício |
| C. Fila externa (Redis, serviço próprio) | Alta | Mais um serviço residente | Fora do modelo de servidor único (ADR-003) |
| **Assinatura: Standard Webhooks** | Baixa | Nenhum | — (bibliotecas prontas em várias linguagens nos receptores) |
| Assinatura própria (HMAC só do corpo) | Baixa | Nenhum | Sem carimbo de tempo, a repetição passa |
| **Chave: LoadCredential ou arquivo 0600** | Baixa | Nenhum | Root lê a chave — aceito: root já controla o servidor |
| Chave derivada de senha digitada no início | Alta | Serviço não sobe sozinho | Inviável para um serviço que reinicia sozinho |

**Consequências.** Mais fácil: nenhuma notificação se perde num reinício; destino lento não atrasa varreduras; o
operador vê na tela o motivo de cada falha e reenvia. Mais difícil: a cópia do banco (E1.14) leva os segredos
cifrados, mas não a chave — restaurar em outro servidor exige copiar `secrets.key` junto (ou informar os segredos de
novo; a tela mostra "ilegível com a chave atual"). Telegram, modelos de Slack/Discord/Teams e saída para SIEM (E2.6)
entram como novos tipos de canal sobre a mesma caixa de saída.
