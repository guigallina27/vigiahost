# VigiaHost — instruções do projeto

## Interface

- Toda tela, componente ou material visual segue o **kit visual** em [`docs/kit-visual.md`](docs/kit-visual.md):
  tokens de `web/src/styles/index.css`, componentes de `web/src/components/` e o catálogo vivo em `/catalogo`
  (`pnpm --dir web dev`).
- Identidade "torre de vigia à noite": tinta azul-grafite, ações em azul-cobalto, âmbar de farol só na marca e no item
  ativo da navegação. **Verde nunca é cor de marca, fundo ou destaque** — só o estado "ok".
- Mudou token ou componente: atualize o kit, o CSS e o catálogo no mesmo commit.
