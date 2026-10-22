import { useEffect, useRef, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Brand } from "../components/BrandMark";

/** Moldura das telas antes do login: marca, título (h1 com foco ao trocar de etapa) e o formulário. */
export function AuthLayout({ title, subtitle, children }: { title: string; subtitle?: ReactNode; children: ReactNode }) {
  const { t } = useTranslation();
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    document.title = `${title} · ${t("app.titleSuffix")}`;
    heading.current?.focus();
  }, [title, t]);
  return (
    <main className="vh-night grid min-h-dvh place-items-center px-4 py-10">
      <div className="flex w-full max-w-md flex-col gap-6">
        <span className="self-center text-nav-ink">
          <Brand size="lg" />
        </span>
        <section className="flex flex-col gap-5 rounded-panel border border-line bg-surface p-6 text-ink shadow-2xl">
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
