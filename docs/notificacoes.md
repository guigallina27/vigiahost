# Notificações — e-mail e webhook assinado

Referência para quem configura os canais e para quem escreve o receptor do webhook. A decisão de arquitetura está no
[ADR-021](adr/0021-notificacoes-e-segredos-de-integracoes.md).

## 1. Como funciona

1. Um evento acontece no core: achado novo ou reaberto, execução com falha ou parcial, motor indisponível ou
   autoteste reprovado, executor fora do ar (e de volta), cópia automática do banco com falha.
2. As **regras** (canal + evento) decidem para onde vai. Achados abaixo da severidade mínima da regra não notificam.
3. A mensagem entra na **caixa de saída** (tabela `notification_outbox`). A mesma chave (achado, execução, motor,
   executor ou cópia do banco) não entra de novo no mesmo canal dentro da janela da regra (padrão: 24 h para
   achados, 6 h para motor e cópia do banco, 1 h para os demais; 0 desliga).
4. Achados novos esperam 60 s para juntar os vizinhos: uma varredura com 500 achados gera **uma** mensagem com a
   contagem por severidade e os 25 primeiros itens (`items_truncated: true` avisa que há mais).
5. O core envia com tempo limite de 20 s. Falha temporária tenta de novo em 30 s, 1 min, 2 min… até 1 h, no máximo
   8 tentativas. Falha definitiva (destino recusado, SMTP 5xx, HTTP 4xx que não seja 408/425/429, redirecionamento)
   encerra na hora. Tudo fica visível em **Configurações › Notificações › Caixa de saída**, com o erro e o botão
   "Reenviar agora".

O botão **Enviar teste** manda uma mensagem do tipo `test` pelo canal e mostra o resultado real (entregue ou o
erro devolvido pelo servidor). O teste não tenta de novo e fica registrado na caixa de saída e na auditoria.

## 2. E-mail (SMTP)

| Segurança | Porta padrão | Comportamento |
|---|---|---|
| `starttls` | 587 | Exige STARTTLS anunciado pelo servidor; nunca cai para texto puro |
| `tls` | 465 | TLS desde a conexão |
| `none` | 25 | Só para relé no próprio servidor (`localhost`, `127.0.0.1`, `::1`) |

- Certificado sempre verificado com as raízes do sistema.
- Usuário opcional; com usuário, a senha é obrigatória e vai por `AUTH PLAIN` (só sobre TLS ou no relé local).
- Até 20 destinatários. Remetente pode ter nome: `VigiaHost <alertas@example.com>`.
- Cabeçalhos `Auto-Submitted: auto-generated` (evita respostas automáticas) e `X-VigiaHost-Event: <evento>`.

## 3. Webhook

### 3.1 Requisição

`POST` para o endereço do canal, `Content-Type: application/json`, `User-Agent: VigiaHost/<versão>` e três
cabeçalhos no padrão [Standard Webhooks](https://www.standardwebhooks.com/):

| Cabeçalho | Conteúdo |
|---|---|
| `webhook-id` | Identificador da mensagem (`msg_<número>`; no envio de teste, `msg_test_<aleatório>`). O mesmo em todas as tentativas da mesma mensagem |
| `webhook-timestamp` | Momento do envio desta tentativa, em segundos Unix |
| `webhook-signature` | `v1,<base64 do HMAC-SHA256>`; pode haver várias separadas por espaço |

O HMAC é calculado sobre o texto `"<webhook-id>.<webhook-timestamp>.<corpo bruto>"`, com a chave do segredo.

### 3.2 Segredo

- Formato recomendado: `whsec_<base64 de 32 bytes>` (o botão "Gerar segredo" da tela produz esse formato). A chave
  do HMAC é o conteúdo **decodificado** do base64.
- Qualquer outro texto é aceito e usado como está, desde que tenha de 24 a 256 bytes.
- Copie o segredo para o receptor antes de salvar: depois de salvo ele é guardado cifrado e **nunca** volta pela API
  nem aparece na tela (só "configurado").
- Para trocar sem perder mensagens: atualize o receptor para aceitar o segredo antigo e o novo, salve o novo no
  canal e depois retire o antigo do receptor.

### 3.3 Corpo

```json
{
  "type": "finding_new",
  "timestamp": "2026-10-22T12:00:00Z",
  "data": {
    "id": "msg_42",
    "server": "web01.example.com",
    "version": "1.0.0",
    "test": false,
    "summary": "12 achados novos (maior severidade: crítica)",
    "count": 12,
    "severity_counts": { "critical": 2, "high": 10 },
    "items": [
      {
        "event": "finding_new",
        "severity": "critical",
        "title": "YARA-X: PHP_Webshell_Generic",
        "detail": "Webshell PHP genérico (descrição da regra)",
        "finding_id": 7,
        "run_id": "run_01J...",
        "engine": "yara-x",
        "path": "/home/cliente/public_html/shell.php",
        "sha256": "e3b0c442...",
        "at": "2026-10-22T11:59:40Z"
      }
    ],
    "items_truncated": false
  }
}
```

- `type`: `finding_new`, `run_failed`, `run_partial`, `engine_selftest_failed`, `executor_unavailable`,
  `backup_failed` ou `test`.
- `items[].resolved: true` aparece na mensagem de "executor de volta".
- `path` e `sha256` só vêm quando o canal tem "Incluir caminhos e hashes" marcado. Conteúdo de arquivo nunca é
  enviado.
- Textos vindos de nomes de arquivo passam por limpeza: caracteres de controle e marcas de direção (bidi) viram
  escapes visíveis. Mesmo assim, trate todo campo como dado não confiável no receptor.
- Novos campos podem aparecer em versões futuras; ignore os que não conhecer.

### 3.4 Como o receptor deve verificar

1. Ler o **corpo bruto** (antes de qualquer interpretação do JSON).
2. Recusar se faltar algum dos três cabeçalhos.
3. Recusar se `webhook-timestamp` estiver a mais de **5 minutos** do relógio local (para frente ou para trás).
4. Calcular `HMAC-SHA256(chave, id + "." + timestamp + "." + corpo)`, codificar em base64 e comparar **em tempo
   constante** com cada assinatura `v1,` do cabeçalho; aceitar se alguma conferir.
5. Guardar os `webhook-id` aceitos por pelo menos 5 minutos e descartar repetidos (responda 2xx ao repetido, para
   o core não tentar de novo).
6. Responder `2xx` rápido (antes de 20 s). Processamento demorado vai para uma fila do receptor.

Python (biblioteca padrão):

```python
import base64, hashlib, hmac, time

def verify(secret: str, headers, body: bytes, tolerance=300) -> bool:
    msg_id = headers.get("webhook-id")
    ts = headers.get("webhook-timestamp")
    sigs = headers.get("webhook-signature")
    if not (msg_id and ts and sigs):
        return False
    if abs(time.time() - int(ts)) > tolerance:
        return False
    key = base64.b64decode(secret.removeprefix("whsec_")) if secret.startswith("whsec_") else secret.encode()
    signed = msg_id.encode() + b"." + ts.encode() + b"." + body
    expected = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    return any(
        s.startswith("v1,") and hmac.compare_digest(s[3:], expected)
        for s in sigs.split(" ")
    )
```

Node.js:

```js
import { createHmac, timingSafeEqual } from "node:crypto";

export function verify(secret, headers, rawBody, toleranceSec = 300) {
  const id = headers["webhook-id"];
  const ts = headers["webhook-timestamp"];
  const sigs = headers["webhook-signature"];
  if (!id || !ts || !sigs) return false;
  if (Math.abs(Date.now() / 1000 - Number(ts)) > toleranceSec) return false;
  const key = secret.startsWith("whsec_") ? Buffer.from(secret.slice(6), "base64") : Buffer.from(secret);
  const expected = createHmac("sha256", key).update(`${id}.${ts}.`).update(rawBody).digest();
  return sigs.split(" ").some((s) => {
    if (!s.startsWith("v1,")) return false;
    const got = Buffer.from(s.slice(3), "base64");
    return got.length === expected.length && timingSafeEqual(got, expected);
  });
}
```

As bibliotecas oficiais do Standard Webhooks (`standardwebhooks` em Python, JavaScript, Go, PHP, Ruby e outras)
também servem.

### 3.5 Respostas e novas tentativas

| Resposta do receptor | Resultado no VigiaHost |
|---|---|
| `2xx` | Enviada |
| `3xx` | Falha definitiva: redirecionamento não é seguido; cadastre o endereço final |
| `408`, `425`, `429`, `5xx`, tempo esgotado, conexão recusada | Nova tentativa com recuo |
| Outros `4xx` (ex.: `401` por assinatura recusada) | Falha definitiva; corrija e use "Reenviar agora" |

Os primeiros 200 caracteres da resposta de erro aparecem na caixa de saída, com caracteres de controle escapados.

### 3.6 Política de rede

O webhook é feito pelo core, que roda dentro do servidor. Para não virar porta de entrada para a rede interna (SSRF):

- Só `http://` e `https://`; sem usuário e senha no endereço; sem fragmento; sem proxy do ambiente; sem seguir
  redirecionamento. Prefira `https`.
- O IP é conferido **na hora da conexão**, para cada endereço que o nome resolver — trocar o DNS depois de salvar
  não contorna a regra.
- **Sempre recusados**, mesmo com rede privada permitida:
  - link-local `169.254.0.0/16` e `fe80::/10` (inclui o serviço de metadados `169.254.169.254` de AWS, GCP, Azure,
    OpenStack e outros);
  - metadados de nuvem fora do link-local: `100.100.100.200` (Alibaba) e `fd00:ec2::254` (AWS IPv6);
  - `0.0.0.0/8`, endereços não especificados e multicast.
- **Só com "Permitir destino na rede privada"** marcado pelo administrador no canal: `127.0.0.0/8`, `::1`,
  `localhost`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `198.18.0.0/15` e `fc00::/7`.
- O SMTP aceita rede privada sem opção extra (relés internos são comuns), mas também recusa link-local e metadados.

## 4. Segredos

- Senha SMTP e segredo do webhook ficam no banco cifrados com AES-256-GCM.
- A chave fica fora do banco: `$CREDENTIALS_DIRECTORY/vigiahost-secrets-key` quando a unidade do core usa
  `LoadCredential=vigiahost-secrets-key:<arquivo>`; senão, `secrets.key` (0600, criado no primeiro início) no
  diretório de estado. O arquivo tem 32 bytes ou o base64 deles (ex.: `openssl rand -base64 32`). Para mudar a origem
  da chave sem perder os segredos já gravados, copie o `secrets.key` atual para o novo arquivo.
- A API devolve só `secret_configured` e `secret_readable`. Logs e auditoria nunca levam o valor.
- A cópia do banco **não** leva a chave. Ao restaurar em outro servidor, copie `secrets.key` junto ou informe os
  segredos de novo (a tela mostra "ilegível com a chave atual").

## 5. Permissões e auditoria

Só administradores veem e alteram a tela. Criar, alterar e remover canais e regras pede reautenticação recente.
Ficam na auditoria: `notification_channel_created`, `notification_channel_updated`, `notification_channel_deleted`,
`notification_rule_created`, `notification_rule_updated`, `notification_rule_deleted`, `notification_test` (com o
resultado) e `notification_retry`. A auditoria guarda o esquema e o servidor do webhook, não o endereço completo.
