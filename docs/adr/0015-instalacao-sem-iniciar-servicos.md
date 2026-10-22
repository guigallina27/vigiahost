# ADR-015: A instalação do pacote não habilita nem inicia os serviços

**Status:** Aceito · **Data:** 22/10/2026 (decidido na implementação da Fase 0)

**Contexto.** No Debian e no Ubuntu é comum o pacote habilitar e iniciar o serviço na instalação; nas famílias RHEL, não. O escopo exige que nada mude no servidor sem que o administrador veja antes (`vigiahost setup plan`) e aplique (`vigiahost setup apply`), e o comportamento precisa ser o mesmo em todas as distribuições.

**Decisão.** Instalar o pacote só cria o usuário de sistema e registra as unidades. Quem habilita e inicia é o `setup apply` (até ele existir, `systemctl enable --now`). Na atualização, o pacote reinicia apenas os serviços do produto que já estavam ativos (`try-restart`), nunca outros serviços. Na remoção, para e desabilita os serviços e preserva dados e usuário; só o *purge* do DEB apaga os dados.

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Instalar sem iniciar; `setup apply` inicia** | Baixa | Nenhum | Igual em todas as distribuições | Baixo |
| B. Seguir a convenção de cada família | Média | Nenhum | Comportamento diferente por distribuição | Serviço no ar antes da configuração revisada |
| C. Sempre iniciar na instalação | Baixa | Nenhum | Igual | Porta aberta e executor root ativos sem revisão |

**Consequências.** Mais fácil: instalar em massa e revisar antes de ativar; comportamento previsível. Mais difícil: o administrador precisa de um passo a mais, que o script de bootstrap encadeia. Revisitar quando o `setup apply` existir, para decidir se o bootstrap o chama por padrão.

**Ações.** [x] Scripts do pacote para DEB e RPM com atualização, retorno e remoção testados em 10 distribuições e com systemd real. [x] `vigiahost setup plan/apply/uninstall` (Fase 1A): plano sem efeito colateral, aplicação idempotente com manifesto em `/etc/vigiahost/setup-manifest.json` e backup em `/var/backups/vigiahost/setup-AAAAMMDD-HHMMSS/`, desinstalação que desfaz o manifesto, com `-purge` opcional; o firewall nunca é alterado (o plano mostra os comandos).
