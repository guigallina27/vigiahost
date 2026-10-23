import { useEffect, useRef, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { useLocation } from "react-router";

// Última rota que recebeu foco; começa na rota da carga inicial, que não deve roubar o foco.
// Comparar rotas (e não contar renderizações) também resiste ao efeito duplo do StrictMode.
let lastFocused: string | null = typeof window === "undefined" ? null : window.location.pathname;

/**
 * Título da página (h1), título do documento e foco na troca de rota: em uma SPA o leitor de tela
 * não percebe a navegação sozinho, então o foco vai para o h1 da nova página (exceto na primeira carga).
 */
export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  const { t } = useTranslation();
  const heading = useRef<HTMLHeadingElement>(null);
  const { pathname } = useLocation();

  useEffect(() => {
    document.title = `${title} · ${t("app.titleSuffix")}`;
  }, [title, t]);

  useEffect(() => {
    if (lastFocused === pathname) return;
    lastFocused = pathname;
    heading.current?.focus();
  }, [pathname]);

  return (
    <header className="vh-grid-texture -mx-4 mb-6 flex flex-wrap items-end justify-between gap-4 border-b border-line px-4 pt-6 pb-5 sm:-mx-8 sm:px-8">
      <div className="min-w-0">
        <h1 ref={heading} tabIndex={-1} className="m-0 text-3xl leading-tight font-bold tracking-tight focus-visible:outline-offset-4">
          {title}
        </h1>
        {subtitle && <p className="m-0 mt-1 text-ink-muted">{subtitle}</p>}
      </div>
      {actions}
    </header>
  );
}
