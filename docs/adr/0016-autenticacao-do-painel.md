# ADR-016: Autenticação do painel web

**Status:** Aceito · **Data:** 22/10/2026 (proposto ao revisar a seção 13 do escopo; aceito e implementado no E1.2, com o item 9 acrescentado a pedido do responsável)

**Contexto.** O escopo já fixa o essencial: usuários próprios do VigiaHost (o glossário separa *usuário* do painel de *conta* do servidor), senha com Argon2id, TOTP, passkeys, códigos de recuperação, sessões no servidor com cookie `__Host-` `Secure` `HttpOnly` `SameSite=Strict`, reautenticação para ações sensíveis, bloqueio progressivo com registro para fail2ban/LFD, perfis administrador, operador, leitura e auditor, tokens de API por hash e token de primeiro acesso exibido no terminal, sem senha padrão. Ficaram em aberto: se o MFA é obrigatório, em que fase entram as passkeys (o escopo diz 1A; o plano, E2.6), como recuperar o acesso quando o único administrador perde senha e MFA, os tempos de sessão e a relação com o login dos painéis de hospedagem.

**Decisão.**

1. **Usuários próprios** no SQLite. Nada de PAM nem de usuários Linux: o painel não deve virar um caminho para testar senhas do sistema, e os perfis do produto não correspondem a grupos do Linux.
2. **MFA obrigatório para administrador e operador** desde a 1A, com TOTP (RFC 6238, janela de ±1 passo, código usado uma vez só) e 10 códigos de recuperação de uso único guardados por hash. Leitura e auditor podem ficar sem MFA se o administrador permitir.
3. **Passkeys/WebAuthn na Fase 2** (E2.6), como segundo fator ou login sem senha. O escopo é corrigido para dizer isso.
4. **Recuperação pelo root**: `vigiahost user reset <usuário>` no terminal do servidor gera um token de uso único com validade de 15 minutos que permite redefinir senha e MFA. O comando exige root e fica registrado na auditoria e no journal. Quem é root no servidor já controla o produto; essa é a mesma premissa do token de primeiro acesso.
5. **Sessões**: 30 minutos de inatividade e 12 horas de duração máxima, ajustáveis pelo administrador dentro de limites (inatividade de 5 a 120 minutos, duração máxima de até 24 horas). O identificador da sessão é trocado no login e na elevação de privilégio. Reautenticação vale por 5 minutos. Trocar a senha ou o MFA encerra as outras sessões do usuário.
6. **Bloqueio progressivo** por usuário e por IP: atraso crescente a partir da 5ª falha e bloqueio temporário de 15 minutos na 10ª, sem revelar se o usuário existe. Cada falha vira uma linha estável no journal (`vigiahost: login falhou user=... ip=...`) para o fail2ban/LFD.
7. **Painéis de hospedagem** (WHM, Webuzo, DirectAdmin): login integrado fica para a Fase 3, como opção que se soma ao login próprio e nunca o substitui. Até lá, o acesso é sempre pelo login do VigiaHost.
8. **Tokens de API** só para automação: escopo por perfil, validade obrigatória (máximo de 1 ano), exibidos uma vez e guardados por hash; não servem para a interface.
9. **Caixa "Não sou um robô" (ALTCHA)** no login, no primeiro acesso e na recuperação: ao marcar a caixa, o navegador resolve uma prova de trabalho (PBKDF2/SHA-256, cerca de 0,5 s num computador comum) sem desafio para o usuário. O servidor (`altcha-lib-go` v2) emite o desafio assinado em `GET /api/v1/auth/challenge`, válido por 10 minutos, em modo determinístico (confere a solução pela assinatura da chave, sem refazer o cálculo) e aceito uma única vez; os segredos HMAC ficam só na memória. A verificação acontece antes de qualquer conferência de senha ou token. O widget `altcha` roda na versão externa (worker próprio e CSS separado), compatível com a CSP sem `unsafe-inline`; sem serviço de terceiros nem rastreamento. Soma-se ao bloqueio progressivo: encarece robôs, não substitui o limite de tentativas.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Usuários próprios + MFA obrigatório para quem altera** | Média | Mínimo (Argon2id ajustado para servidores pequenos) | Igual em todas as distribuições e painéis | Baixo |
| B. PAM / usuários do Linux | Baixa | Nenhum | Depende da configuração de cada servidor | Painel vira alvo de força bruta das senhas do sistema; perfis não se mapeiam |
| C. Só login pelo painel de hospedagem | Alta | Nenhum | Uma integração por painel; sem painel, sem acesso | Dependência de terceiros para a segurança do produto |
| D. MFA opcional para todos | Baixa | Nenhum | Igual | Conta de administrador sem segundo fator controlando quarentena e exceções |

**Trade-offs.** A exige que o operador configure um app autenticador no primeiro acesso, o que é um passo a mais; em troca, uma senha vazada não basta para mover arquivos para a quarentena nem criar exceções. A recuperação pelo root não abre caminho novo de ataque, porque o root já pode ler o banco e parar o serviço.

**Consequências.** Mais fácil: comportamento igual com ou sem painel de hospedagem; auditoria completa de quem fez cada ação. Mais difícil: o suporte precisa orientar a recuperação pelo terminal. Revisitar quando entrarem as passkeys (talvez dispensar senha) e quando a central (Fase 4) trouxer login único entre servidores.

**Ações.** [x] Aceitar esta proposta (com o item 9). [x] Implementar no E1.2 com testes da matriz de autorização, da troca de identificador de sessão, do bloqueio progressivo e do ALTCHA (reuso, adulteração, expiração). [x] Corrigir a seção 13 do escopo (passkeys na Fase 2, MFA obrigatório, recuperação pelo root, tempos de sessão, ALTCHA). [ ] Tempos de sessão ajustáveis pelo administrador (hoje fixos nos valores padrão).
