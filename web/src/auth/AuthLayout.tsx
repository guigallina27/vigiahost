import { useEffect, useRef, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

/** Moldura das telas antes do login: marca, título (h1 com foco ao trocar de etapa) e o formulário. */
export function AuthLayout({ title, subtitle, children }: { title: string; subtitle?: ReactNode; children: ReactNode }) {
  const { t } = useTranslation();
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    document.title = `${title} · ${t("app.titleSuffix")}`;
    heading.current?.focus();
  }, [title, t]);
  return (
    <main className="vh-grid-texture grid min-h-dvh place-items-center px-4 py-10">
      <div className="flex w-full max-w-md flex-col gap-6">
        <span className="flex items-center gap-2.5 self-center">
          <svg aria-hidden="true" viewBox="0 0 32 32" className="size-9 shrink-0">
            <rect width="32" height="32" rx="7" fill="oklch(33% 0.04 175)" />
            <path d="M7 9l9 16 9-16" fill="none" stroke="oklch(95% 0.01 150)" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round" />
            <circle cx="16" cy="9.5" r="2.6" fill="var(--vh-signal)" />
          </svg>
          <span className="text-xl font-bold tracking-tight">VigiaHost</span>
        </span>
        <section className="flex flex-col gap-5 rounded-panel border border-line bg-surface p-6 shadow-panel">
          <div>
            <h1 ref={heading} tabIndex={-1} className="m-0 text-2xl leading-tight font-bold">
              {title}
            </h1>
            {subtitle && <p className="m-0 mt-1 text-ink-muted">{subtitle}</p>}
          </div>
          {children}
        </section>
      </div>
    </main>
  );
}
