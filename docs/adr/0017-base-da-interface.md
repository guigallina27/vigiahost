# ADR-017: Base da interface: contrato gerado, design system e cadeia de suprimentos do front-end

**Status:** Aceito · **Data:** 22/10/2026 (decidido na implementação do E0.4 e do E0.6)

**Contexto.** O escopo (seções 6.3, 14 e 19) pede React embarcado no binário, cliente gerado do mesmo OpenAPI do servidor, i18n, WCAG 2.1 AA nos dois temas, fontes e ícones sem CDN, compatibilidade com a CSP e um catálogo de componentes com teste de acessibilidade. Faltava escolher as peças e o que fazer onde o ecossistema não acompanha (ex.: plugins de lint atrasados em relação ao ESLint e ao TypeScript).

**Decisão.**

| Tema | Escolha | Motivo |
|---|---|---|
| Contrato | `api/openapi.yaml` (3.0.3) → oapi-codegen v2.8.0 (`models` + `std-http-server` sobre o `ServeMux`) e openapi-typescript + openapi-fetch; `make check-generated` falha se o gerado divergir | Um contrato, dois lados tipados; o código gerado só usa `net/http`, sem dependência em tempo de execução |
| Entrega | Build do Vite em `internal/webui/dist`, embarcado com `go:embed`; `/assets/*` com hash e `Cache-Control: immutable`; versões `.br`/`.gz` geradas no build e escolhidas pelo `Accept-Encoding`; rotas sem extensão recebem o `index.html`; `/api/*` inexistente responde 404 em JSON | Um binário, sem servidor de arquivos externo; métodos errados na API continuam com 405 porque a interface fica em `GET /` |
| CSP | `default-src 'self'` sem exceções: nenhum script ou estilo embutido no HTML, `assetsInlineLimit: 0`; o script que aplica o tema antes da primeira pintura é um arquivo próprio (`/theme-init.js`) | XSS por nome de arquivo é a ameaça principal da interface (modelo de ameaças, 3.1) |
| Tema | Segue o sistema; a escolha manual (Sistema/Claro/Escuro em Configurações) troca o `<meta name="color-scheme">`, refletido no CSS por `:has()`; tokens com `light-dark()` | Sem classe `.dark` dependente de JS; funciona mesmo se o JS falhar |
| Navegadores | Baseline 2024 (`light-dark()`, `:has()`, `<dialog>`); recursos mais novos só como melhoria progressiva (ex.: `closedby`) | Painel administrativo usado por operadores com navegador atualizado; evita *polyfills* |
| Componentes | Próprios, sobre HTML nativo (`<dialog>` com `showModal()`, `fieldset`/`radio`, `<time>`), Tailwind v4 e ícones lucide-react (ISC). shadcn/ui e Radix entram só quando surgir um padrão que o HTML nativo não cubra (ex.: combobox, menu de ações) | Menos dependências e foco/teclado do próprio navegador |
| Tipografia | Atkinson Hyperlegible Next e Mono (OFL-1.1), variáveis e embarcadas | Diferenciam `0/O`, `1/l/I` e `rn/m`, o que importa em hashes e caminhos |
| i18n | i18next + react-i18next, pt-BR padrão e inglês completo; teste garante as mesmas chaves nos dois | Tipagem das chaves e textos no bundle, sem requisição extra |
| Catálogo | Rota `/catalogo` só no servidor de desenvolvimento (removida do build), com axe-core via Playwright nos dois temas, teste de teclado, foco, Esc no diálogo, troca de tema e reflow em 320 px | Cobre o pedido do escopo sem as ~200 dependências do Storybook |
| Gerenciador de pacotes | pnpm (versão fixada em `packageManager`, instalada pelo corepack) com `minimumReleaseAge` de 7 dias, `strictDepBuilds` e `--frozen-lockfile` | Mesma espera do Dependabot; nenhum pacote roda script de instalação sem revisão |
| Licenças | `web/scripts/licenses.mjs` confere as dependências de produção (MIT, ISC, BSD, Apache-2.0, MPL-2.0, OFL-1.1...) e gera `licencas-terceiros.txt`, embarcado e servido pelo painel | Mesmo critério do go-licenses e cumprimento dos avisos exigidos por MIT/ISC |
| Ferramentas | TypeScript 6.0 (o typescript-eslint ainda não aceita o 7); ESLint 10 com eslint-plugin-jsx-a11y 6.10 (declara suporte até o 9, mas roda sem erro no 10; revisar quando sair versão nova ou trocar pelo fork mantido) | ESLint 9 está fora de suporte |

| Opção de catálogo | Complexidade | Custo no servidor | Escala | Risco |
|---|---|---|---|---|
| **A. Rota de desenvolvimento + Playwright/axe** | Baixa | Nenhum (fora do build) | Boa até dezenas de componentes | Documentação menos rica que a do Storybook |
| B. Storybook com addon de acessibilidade | Média | Nenhum | Boa | Centenas de dependências de desenvolvimento a mais |
| C. Sem catálogo, só testes unitários | Baixa | Nenhum | Ruim para revisão visual | Contraste e foco sem verificação nos dois temas |

**Consequências.** Mais fácil: qualquer mudança no contrato quebra o build dos dois lados; acessibilidade verificada a cada mudança; pacote sem dependência de rede. Mais difícil: componentes complexos (combobox, tabela virtualizada) precisam ser escritos ou adotados com cuidado. Revisitar se o catálogo passar de ~40 componentes (Storybook pode compensar) e quando o typescript-eslint aceitar o TypeScript 7.

**Ações.** [x] Contrato e geração (E0.4). [x] Tokens, navegação, componentes, Visão geral, Configurações e catálogo com testes (E0.6). [x] Job da interface no CI e Dependabot para npm. [ ] Reautenticação real e indicador do SSE (E1.2). [ ] Fuso do servidor na API para o `Timestamp`.
