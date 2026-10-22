import type { ReactNode } from "react";

type Props = {
  /** Nome da região para leitores de tela; em geral, o mesmo texto da legenda (caption) da tabela. */
  label: string;
  children: ReactNode;
};

/**
 * Contêiner de tabela que rola na horizontal sem alargar a página (WCAG 1.4.10). A região é nomeada e recebe foco
 * para quem usa só o teclado conseguir rolá-la quando a tabela não tem links nem botões (WCAG 2.1.1).
 */
export function TableScroll({ label, children }: Props) {
  return (
    // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- região rolável nomeada, exceção prevista na regra
    <div className="vh-table-wrap" role="region" aria-label={label} tabIndex={0}>
      {children}
    </div>
  );
}
