# Kit visual do VigiaHost

Referência obrigatória para qualquer tela, componente ou material visual do produto. O kit vive em três lugares que
precisam concordar entre si:

| Onde | O que guarda |
|---|---|
| Este documento | Conceito, regras de uso e o que não fazer |
| [`web/src/styles/index.css`](../web/src/styles/index.css) | Tokens (`--vh-*`) com `light-dark()`, classes utilitárias (`vh-label`, `vh-table`, `vh-night`…) |
| Catálogo vivo em `/catalogo` (só no `pnpm dev`) | Marca, tokens e componentes renderizados nos dois temas, cobertos pelo teste de acessibilidade |

Mudou um token ou um componente? Atualize os três no mesmo commit.

## 1. Conceito: torre de vigia à noite

O produto vigia servidores enquanto o operador não está olhando. A identidade parte disso:

- **Tinta azul-grafite** nas superfícies escuras e na navegação (o "console" do operador), papel frio no tema claro.
- **Azul-cobalto** para tudo que é ação: botão principal, link, seleção, barra de progresso.
- **Âmbar de farol** como sinal da marca: o farol do logotipo e o marcador do item ativo da navegação. Só isso.
- **Cores de estado** (crítico, alto, médio, baixo, ok) existem para informar risco, nunca para decorar.

**Proibido como cor de marca, fundo, navegação ou destaque: verde e verde-azulado.** Verde aparece apenas no
estado "ok" (concluído, operacional, resolvido). Também fora: gradientes roxos, neon, fundos chapados genéricos.

## 2. Cores

Todas em OKLCH, definidas uma vez em `:root` com `light-dark(claro, escuro)`. Nunca escreva cor solta em componente:
use o token (`text-ink`, `bg-surface`, `text-(--vh-critical-fg)`…).

| Token | Papel | Claro | Escuro |
|---|---|---|---|
| `--vh-bg` | Fundo da página | papel frio 97,6% | tinta 16,5% |
| `--vh-surface` | Painéis, diálogos, cartões | 99,5% | 20,5% |
| `--vh-sunken` | Áreas rebaixadas (código, objeto do diálogo, cabeçalho de tabela) | 94,8% | 14% |
| `--vh-ink` / `--vh-ink-muted` | Texto principal / secundário | tinta 21% / 44% | 94,5% / 76% |
| `--vh-line` | Separador decorativo | — | — |
| `--vh-line-strong` | Borda de controle (≥ 3:1, WCAG 1.4.11) | — | — |
| `--vh-accent`, `-ink`, `-soft` | Ação (cobalto, matiz 264), texto sobre ela, fundo suave | 47% | 77% |
| `--vh-signal` | Farol âmbar (matiz 75) — **só marca e item ativo** | 81% | 81% |
| `--vh-focus` | Anel de foco | cobalto escuro | âmbar claro |
| `--vh-nav-*` | Navegação lateral em tinta nos dois temas | — | — |

Estados (sempre ícone + texto; a cor é reforço, WCAG 1.4.1):

| Tom | Matiz | Uso |
|---|---|---|
| `critical` | vermelho 25 | Crítico, falha, indisponível, ação destrutiva |
| `high` | laranja 45–60 | Alto |
| `medium` | âmbar-mostarda 80–90 | Médio, parcial, atenção |
| `low` | azul-aço 225 | Baixo, informativo em andamento (distante do cobalto das ações) |
| `ok` | verde 150 | Concluído, operacional, resolvido — **único lugar do verde** |
| `neutral` | grafite 264 | Na fila, cancelado, exceção |

Severidade usa selo **preenchido** (o que é); estado usa selo **contornado** (em que pé está). Um conceito, uma forma.

## 3. Marca

- Componente [`BrandMark`/`Brand`](../web/src/components/BrandMark.tsx): quadrado cobalto profundo, o "V" da torre em
  branco e o farol âmbar com dois fachos. "Vigia" na cor do texto, "Host" em âmbar.
- Sempre acompanhada do nome em texto; o SVG é decorativo (`aria-hidden`).
- Não recolorir, não girar, não aplicar sombra ou contorno. Área livre mínima: metade da altura da marca.
- A marca com o nome (`Brand`) vai sempre sobre fundo noturno (navegação, telas de acesso, `.vh-night`): o "Host" em
  âmbar não tem contraste sobre superfície clara. Em fundo claro, use só o símbolo (`BrandMark`).

## 4. Tipografia

- **Atkinson Hyperlegible Next** (texto) e **Atkinson Hyperlegible Mono** (caminhos, hashes, versões, comandos),
  servidas localmente pelo `@fontsource` — escolhidas pela legibilidade de caracteres parecidos (0/O, 1/l/I), vital
  em hashes e caminhos.
- Hierarquia: título da página `text-3xl font-bold tracking-tight`; título de painel em `vh-label` (mono, caixa alta
  espaçada); corpo 16 px; texto auxiliar `text-sm text-ink-muted`.
- Números em tabelas com `tabular-nums`. Datas sempre pelo componente `Timestamp` (relativa + absoluta + fuso).

## 5. Superfícies, forma e profundidade

- Raios: `rounded-control` (0,375 rem) em controles; `rounded-panel` (0,625 rem) em painéis e diálogos.
- Profundidade discreta: `shadow-panel` nos painéis; `shadow-2xl` só em diálogo e no cartão das telas de acesso.
- Texturas permitidas: malha pontilhada no cabeçalho das páginas (`vh-grid-texture`) e o céu noturno com facho do
  farol e anéis de varredura nas telas de acesso (`vh-night`). Nada além disso.
- Espaçamento em múltiplos de 4 px; respiro entre painéis `gap-6`; dentro do painel `gap-4`, `p-5`.

## 6. Componentes

Use os existentes antes de criar outro (todos em `web/src/components/`): `Button` (primary, secondary, danger,
ghost), `Field`/`SelectField`/`TextAreaField`/`FormError`, `Panel`, `PageHeader`, `EmptyState`, `Badge`,
`SeverityBadge`, `SeverityCounts`, `StatusBadge`, `PathText`, `HashText`, `Timestamp`, `CoverageBar`, `EngineHealth`,
`ConfirmDialog`, `FilterChip`, `CaptchaField`, `BrandMark`, `TableScroll`. Tabelas: `<TableScroll label="…"><table class="vh-table">` com `caption`
e `th scope`; o `TableScroll` rola no próprio contêiner e é uma região nomeada que recebe foco (WCAG 2.1.1 e 1.4.10).

- `SeverityCounts`: achados abertos por severidade, selo + número. `layout="inline"` (células de tabela) mostra só as
  severidades com achados e "Nenhum achado aberto" quando zera; `layout="grid"` (painéis) mostra todas e, com `hrefFor`,
  cada cartão vira link para a lista filtrada.
- `FilterChip`: filtro aplicado que chega por link de outra tela (ex.: `?account=` nos achados e nas execuções), com o
  valor visível e botão de remover de 44 px com nome próprio. Não substitui os campos do formulário de filtros.

Componente novo reutilizável: entra no catálogo `/catalogo` com variantes e estados antes de ser usado em páginas.

## 7. Escrita

- pt-BR, frases curtas, linguagem do operador de hospedagem; inglês completo nas traduções (`web/src/i18n`).
- Botão = verbo + objeto ("Iniciar verificação", "Revogar exceção"); nunca "OK" ou "Enviar".
- Estado vazio diz o que aconteceu e o próximo passo; erro diz a causa e onde conferir.
- Ação sensível: `ConfirmDialog` com objeto exato, impacto e se é reversível; reautenticação quando o servidor exige.

## 8. Acessibilidade e responsividade (não negociáveis)

- WCAG 2.1 AA nos dois temas e no modo de cores forçadas; foco visível próprio (`--vh-focus`); alvos ≥ 44 px.
- De 320 px a telas largas e com zoom de 200% sem rolagem horizontal da página (tabelas rolam no próprio contêiner);
  `min-w-0` em filhos de flex/grid; caminhos e hashes quebram sem estourar (`PathText`, `[overflow-wrap:anywhere]`).
- Movimento só com `motion-safe:`; nada pisca nem gira sem necessidade.
- CSP do core sem `unsafe-inline`: nada de `style=""` em HTML, `data:` ou scripts de terceiros.

## 9. Checklist antes de entregar uma tela

1. Só tokens do kit; nenhum verde fora do estado "ok"; âmbar só na marca e no item ativo.
2. Conferida nos temas claro e escuro, a 320 px e a 200% de zoom.
3. Estados de carregamento, vazio e erro presentes.
4. Textos nos dois idiomas; botões com verbo + objeto.
5. Componente novo adicionado ao catálogo; teste de acessibilidade (`pnpm run test:a11y`) passando.
