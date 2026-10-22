import { Check, Copy, TriangleAlert } from "lucide-react";
import { useEffect, useId, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "../../components/Button";
import { escapeHidden } from "../../lib/text";

type CopyState = "idle" | "copied" | "failed";

/**
 * Segredo exibido uma única vez (token de API, senha inicial): valor completo, botão de copiar, aviso e um botão
 * explícito para fechar depois de guardado. O valor só existe no estado da tela; não vai para cache nem armazenamento.
 */
export function SecretOnce({
  title,
  label,
  value,
  warning,
  children,
  doneLabel,
  onDone,
}: {
  title: string;
  label: string;
  value: string;
  warning: string;
  children?: ReactNode;
  doneLabel: string;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const [state, setState] = useState<CopyState>("idle");
  const titleId = useId();

  useEffect(() => {
    if (state === "idle") return;
    const timer = setTimeout(() => setState("idle"), 2500);
    return () => clearTimeout(timer);
  }, [state]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      setState("failed");
    }
  }

  return (
    <section
      aria-labelledby={titleId}
      className="flex min-w-0 flex-col gap-4 rounded-panel border-2 border-(--vh-medium-fg) bg-surface p-5 shadow-panel"
    >
      <h2 id={titleId} className="m-0 text-lg font-bold">
        {title}
      </h2>
      <p className="m-0 flex items-start gap-2 rounded-control bg-(--vh-medium-bg) p-3 text-(--vh-medium-fg)">
        <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
        <span className="min-w-0">{warning}</span>
      </p>
      <div className="grid min-w-0 gap-1">
        <span className="font-semibold">
          {label}
        </span>
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <code
            translate="no"
            className="min-w-0 flex-1 rounded-control bg-sunken p-3 font-mono text-base [overflow-wrap:anywhere] select-all"
          >
            {escapeHidden(value)}
          </code>
          <Button onClick={copy}>
            {state === "copied" ? (
              <Check aria-hidden="true" className="size-4 text-(--vh-ok-fg)" />
            ) : (
              <Copy aria-hidden="true" className="size-4" />
            )}
            {t("admin.common.copy")}
          </Button>
        </div>
        <span role="status" className={state === "failed" ? "text-sm text-(--vh-critical-fg)" : "text-sm text-(--vh-ok-fg)"}>
          {state === "copied" ? t("admin.common.copied") : state === "failed" ? t("admin.common.copyFailed") : ""}
        </span>
      </div>
      {children}
      <div>
        <Button variant="primary" onClick={onDone}>
          {doneLabel}
        </Button>
      </div>
    </section>
  );
}

/** Texto vindo do servidor (nomes, alvos, detalhes) com caracteres invisíveis e de direção à mostra. */
export function SafeText({ value, mono = false }: { value: string; mono?: boolean }) {
  return (
    <span dir="auto" className={`[overflow-wrap:anywhere] [unicode-bidi:isolate] ${mono ? "font-mono text-[0.9375em]" : ""}`}>
      {escapeHidden(value)}
    </span>
  );
}
