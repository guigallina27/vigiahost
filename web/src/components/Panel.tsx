import type { ReactNode } from "react";

type Props = { title: string; titleId?: string; children: ReactNode; actions?: ReactNode };

/** Painel de conteúdo com título h2; não vira landmark (sem aria-label), para não poluir a navegação por regiões. */
export function Panel({ title, titleId, children, actions }: Props) {
  return (
    <section className="flex min-w-0 flex-col gap-4 rounded-panel border border-line bg-surface p-5 shadow-panel">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 id={titleId} className="vh-label m-0 text-ink-muted">
          {title}
        </h2>
        {actions}
      </div>
      {children}
    </section>
  );
}
