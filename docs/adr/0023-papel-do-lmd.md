# ADR-023: LMD como fonte adicional de assinaturas, opcional e desligado por padrão

**Status:** Aceito · **Data:** 22/10/2026 (decidido no E1.10 com as medições do laboratório; fecha a decisão pendente
da seção 23 do escopo)

**Contexto.** O Linux Malware Detect (LMD, projeto rfxn) é comum em servidores de hospedagem e traz assinaturas
voltadas a webshells e injeções em PHP. Na instalação padrão ele copia as próprias assinaturas (`rfxn.hdb`, `rfxn.ndb`,
`rfxn.yara`) para os diretórios do ClamAV e manda o clamd recarregar: no servidor típico o clamd que o VigiaHost já usa
carrega boa parte do LMD. Rodar o `maldet` por cima repetiria o mesmo conteúdo, com custo de tempo e riscos próprios
(quarentena, alertas e ganchos que agem sozinhos, script em shell rodando como root). O escopo (seções 7.2 e 23) pedia
medir a sobreposição antes de decidir.

**Medições** (laboratório WSL AlmaLinux 9.8, 16 vCPUs; LMD 2.0.1 do release oficial, conferido por SHA-256,
assinaturas 2026052490478; ClamAV 1.4.6 com a base oficial; `gencorpus sobreposicao`, lotes de 5.000 arquivos):

| Corpus | Arquivos | LMD (adaptador) | ClamAV oficial (`clamscan`) | ClamAV só com `rfxn.*` | Interseções |
|---|---|---|---|---|---|
| Positivos (EICAR, ZIP aninhado, PHP ofuscado, marcadores) | 14 | 3 em 8,6 s | 3 em 8,8 s | 4 em 0,5 s | LMD ∩ rfxn no ClamAV = 3; só LMD = 0; LMD ∩ oficial = 2; LMD fora de (oficial ∪ rfxn) = 0 |
| Benigno (WordPress, WooCommerce, Joomla, Drupal, phpMyAdmin) | 47.692 | 0 em 115,1 s | 0 em 648,6 s | 0 em 477,7 s | Nenhum falso positivo em nenhum dos três |
| Sintético (nomes especiais, marcadores YARA inertes) | 20.006 | 0 em 44,5 s | 0 em 184,5 s | 0 em 160,9 s | Nenhuma detecção nos três (esperado: os marcadores são só do YARA) |

- Tudo o que o LMD achou o ClamAV com as `rfxn.*` também achou; o único achado a mais do lado do ClamAV foi o ZIP
  aninhado (o clamd descompacta; o LMD não).
- O conjunto do LMD 2.0.1 tem 45.385 MD5, 42.634 SHA-256, 2.373 HEX, 86 assinaturas compostas (CSIG) e 3.706 YARA.
  No ClamAV entram as MD5 (`rfxn.hdb`), as HEX (`rfxn.ndb`) e as YARA (`rfxn.yara`). Com `scan_hashtype=auto` o LMD
  usa as SHA-256 no lugar das MD5; elas e as CSIG ficam fora do clamd (a 2.0.1 não publica `rfxn.hsb` e o ClamAV não lê
  as CSIG). Hipótese não conferida amostra a amostra: as SHA-256 são do mesmo acervo das MD5 (quantidades próximas).
- Com o LMD ligado, a varredura de 14 positivos na unidade transitória do produto foi de 9 s para 22 s: cada lote
  custa cerca de 6,5 s fixos (o `maldet` carrega as assinaturas) mais o autoteste. Arquivos limpos ficam no cache
  incremental com a versão do LMD; na segunda execução só os detectados voltaram ao LMD.

**Decisão.**

1. O LMD é um **motor opcional e desligado por padrão**: fonte adicional de assinaturas (MD5, SHA-256, HEX, CSIG e YARA
   do rfxn), ligada pelo administrador na tela Regras e fontes. Ligar exige o LMD 2.x instalado; o produto detecta,
   mostra "não instalado" com orientação e nunca instala ferramentas de terceiros. O LMD 1.6 não é suportado (sem
   `LMD_BASEDIR` nem relatório JSON).
2. Quando ligado, recebe **a mesma lista do inventário**, por descritor (`/proc/<pid>/fd/N` do processo da varredura,
   [ADR-018](0018-arquivos-aos-motores-por-descritor.md)), com o mesmo roteamento por tipo do YARA-X e a faixa de tamanho
   padrão do próprio LMD (24 B a 2 MiB); fora dela o arquivo não é elegível para o LMD e segue coberto pelo YARA-X e pelo
   ClamAV.
3. O VigiaHost **só lê**: cada execução força por `-co` quarentena, suspensão de usuário, estágio ClamAV
   (`scan_clamscan=0`), alertas (e-mail, Slack, Telegram, Discord), estatísticas, exportação de lista e ganchos
   desligados, e usa uma base própria (`LMD_BASEDIR`) com `tmp`, `sess` e `pub` da execução e o caminho da quarentena
   bloqueado. Relatório com quarentena ligada é recusado e vira falha do motor.
4. O resultado vem do `--json-report` (esquema 1.x), com o `session.tsv` como reserva; campos com tamanho limitado,
   assinaturas do LMD e do clamd com prefixo `{MD5}`/`{HEX}`/`{SHA256}`/`{YARA}` contam como a mesma **fonte de
   assinatura** (`rfxn`) para a correlação (escopo, seção 10).
5. A tela Regras e fontes mostra quando as `rfxn.*` já estão nos diretórios do ClamAV. Recomendação de operação: manter
   o LMD desligado quando o clamd já carrega as `rfxn.*`; ligar quando o servidor tem o LMD sem a integração com o
   ClamAV ou quando se quer também as CSIG.

| Opção | Complexidade | Custo no servidor | Ganho de detecção medido | Risco |
|---|---|---|---|---|
| **A. Opcional, desligado por padrão, só leitura** | Média | Nenhum se desligado; ~6,5 s por lote se ligado | Nenhum além do clamd com `rfxn.*`; SHA-256 e CSIG sem o clamd | Baixo: quarentena e ações desligadas à força |
| B. Sempre ligado quando instalado | Média | ~6,5 s por lote em toda varredura | Igual ao A | Repete o clamd; mais tempo na janela da rotina |
| C. Não integrar | Nenhuma | Nenhum | — | Perde as CSIG e o LMD de servidores sem integração com o ClamAV |
| D. Usar o `maldet` como ele roda sozinho (`-a`, com estágio ClamAV) | Baixa | Alto | Repete o clamd por inteiro | Quarentena e ações próprias; motor percorre diretórios por nome |

**Consequências.** Mais fácil: o administrador escolhe; a cobertura mostra o LMD como motor próprio, com autoteste
(EICAR em memória), versão do motor e das assinaturas. Mais difícil: o `maldet` é um script em shell que roda como root
dentro da unidade da varredura; o isolamento da unidade (sistema só leitura, sem rede, só `CAP_DAC_*`) é o que contém
efeitos colaterais. Exemplo encontrado no laboratório: com `scan_clamscan=0`, o LMD 2.0.1 tenta apagar as `rfxn.*` dos
diretórios do ClamAV (`clamav_unlinksigs`); na unidade o sistema é só leitura e nada é apagado, mas rodar o `maldet`
fora do produto com essa opção apaga. O `test/lab/install-lmd.sh` instala o LMD no laboratório sem tocar no ClamAV
(diretórios do ClamAV cobertos por `tmpfs` durante o `install.sh`). Revisitar se o rfxn passar a publicar `rfxn.hsb`
(aí o clamd cobriria também as SHA-256) ou se o LMD trouxer detecção que não seja por assinatura.

**Ações.**
- [x] Adaptador, autoteste, cobertura e achados do motor `lmd` (E1.10).
- [x] Tela Regras e fontes com ligar/desligar, auditoria e reautenticação.
- [ ] Repetir a medição num servidor de produção com o LMD instalado pelo administrador (validação em servidores próprios).
