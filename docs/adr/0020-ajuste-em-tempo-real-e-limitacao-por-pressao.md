# ADR-020: Ajuste em tempo real pelo executor e limitação por pressão dentro da execução

**Status:** Aceito · **Data:** 22/10/2026 (decidido na implementação do E1.13)

**Contexto.** O [ADR-012](0012-perfis-de-recursos.md) previu ajuste em tempo real e o escopo (seção 12) pede que a
varredura recue quando o servidor está sob pressão. Faltava decidir três pontos:

- onde mora o perfil efetivo de uma execução em andamento;
- como o ajuste chega à unidade transitória sem abrir um caminho que contorne as travas;
- quem decide reduzir o ritmo pela pressão (PSI) e onde ficam as medidas.

**Decisão.**

1. **Operação tipada `run.adjust` (protocolo 1.2).** O core envia só os campos que mudam: CPU, memória, banda de
   leitura, peso de E/S e o pedido de liberar a reserva. O executor faz o seguinte:
   - lê o perfil efetivo da execução (`limits.json`, gravado por ele no diretório da execução; na ausência, o perfil
     do pedido);
   - mescla os campos novos e reaplica `profile.Enforce` com o hardware que o executor detectou;
   - exige a unidade `vigiahost-run-<id>.service` ativa;
   - aplica por `SetUnitProperties` (D-Bus, `runtime=true`) só as propriedades que mudaram: `CPUQuotaPerSecUSec`,
     `MemoryMax`, `IOReadBandwidthMax` e `IOWeight`;
   - grava o novo `limits.json` de forma atômica.

   Workers, prioridade (`Nice`), duração máxima e limiares de pressão não mudam com a execução em andamento: valem a
   partir da próxima.
2. **A API não contorna as travas.** Liberar a reserva só vale com a liberação local do executor (`AllowNoReserve`).
   As faixas técnicas valem sempre. A rota `POST /runs/{id}/adjust` exige papel de administrador e reautenticação, e
   cada ajuste gera auditoria (`run_limits_adjusted`, com antes e depois). O histórico também fica na própria execução
   (`runs.adjustments`, no máximo 50).
3. **Limitação por PSI no runner, dentro da unidade.** O runner lê `/proc/pressure/{cpu,io,memory}` (linha `some`,
   `avg10`) a cada amostra e compara com os limiares do perfil:
   - **reduzir:** acima do limiar, corta o paralelismo pela metade;
   - **pausar:** com 1,5× o limiar ou com um só worker, suspende os lotes;
   - **retomar:** depois de 3 amostras abaixo de 70% do limiar, dobra o paralelismo até o do perfil.

   Os eventos (até 200), o tempo limitado e o tempo pausado vão para o resumo. O estado atual vai para o progresso
   (`runs.throttle`).
4. **Métricas no resumo.** Ficam no resumo da execução:
   - duração por etapa;
   - CPU (`cpu.stat`) e pico de memória (`memory.peak`, com amostragem de `memory.current` como reserva) do cgroup
     da própria unidade, ou `getrusage` fora dela;
   - bytes lidos;
   - limitação.

   O comparativo lê as últimas N execuções terminadas do mesmo tipo (índice `runs_kind_finished`, migração 00008).

| Opção | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Operação tipada com perfil efetivo no executor + PSI no runner** | Média | Uma leitura de `/proc/pressure` por amostra | Boa | Baixo: a trava é a mesma do início da execução |
| B. Core recalcula e manda as propriedades prontas | Baixa | Nenhum | Boa | Core comprometido escolhe propriedades e valores; trava duplicada |
| C. Executor observa a PSI e congela a unidade inteira | Média | Igual | Boa | Pausa grosseira, sem redução gradual; disputa com a pausa do operador |
| D. Ajuste por reinício da execução com perfil novo | Baixa | Releitura do que já foi feito | Ruim | Perde o ritmo e confunde o histórico |

**Consequências.**

- **Mais fácil:**
  - aliviar uma execução pesada sem cancelá-la;
  - a varredura recua sozinha quando o servidor aperta;
  - o operador vê quanto tempo a execução passou limitada.
- **Mais difícil:**
  - o perfil efetivo vive em dois lugares (perfil do pedido e `limits.json`);
  - o core consulta o estado para mostrar os limites atuais.
- **Revisitar:**
  - mudança de workers em tempo real, se o histórico mostrar necessidade;
  - `ionice` explícito, se `IOWeight` e banda não bastarem em discos rotacionais.

**Ações.**

- [x] Teste em systemd real: ajuste muda `cpu.max` e `memory.max` da unidade.
- [x] Teste em systemd real: pedido acima da reserva é recusado sem a liberação local.
- [x] Teste em systemd real: unidade parada responde `not_found`.
- [x] Teste do runner com pressão injetada: reduz, pausa e retoma.
