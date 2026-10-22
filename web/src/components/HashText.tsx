import { Check, Copy } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

type Props = {
  value: string;
  algorithm?: string;
  /** Caracteres visíveis antes das reticências. */
  visible?: number;
};

type CopyState = "idle" | "copied" | "failed";

/** Hash abreviado na tela, com o valor completo para leitores de tela e um botão de copiar (escopo, seção 14.2). */
export function HashText({ value, algorithm = "SHA-256", visible = 12 }: Props) {
  const { t } = useTranslation();
  const [state, setState] = useState<CopyState>("idle");

  useEffect(() => {
    if (state === "idle") return;
    const timer = setTimeout(() => setState("idle"), 2500);
    return () => clearTimeout(timer);
  }, [state]);

  const short = value.length > visible ? `${value.slice(0, visible)}…` : value;

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      setState("failed");
    }
  }

  return (
    <span className="inline-flex max-w-full items-center gap-1 align-middle">
      <code className="font-mono text-[0.9375em] tabular-nums" translate="no">
        <span aria-hidden="true">{short}</span>
        <span className="visually-hidden">{t("hash.full", { algorithm, value })}</span>
      </code>
      <button
        type="button"
        onClick={copy}
        className="inline-grid size-8 shrink-0 cursor-pointer place-items-center rounded-control border border-transparent text-ink-muted hover:border-line-strong hover:text-ink pointer-coarse:size-11"
      >
        {state === "copied" ? (
          <Check aria-hidden="true" className="size-4 text-(--vh-ok-fg)" />
        ) : (
          <Copy aria-hidden="true" className="size-4" />
        )}
        <span className="visually-hidden">{t("hash.copy", { algorithm })}</span>
      </button>
      {/* Região de status só para o resultado da cópia (WCAG 4.1.3), sem anunciar o hash inteiro de novo. */}
      <span role="status" className={state === "failed" ? "text-sm text-(--vh-critical-fg)" : "visually-hidden"}>
        {state === "copied" ? t("hash.copied", { algorithm }) : state === "failed" ? t("hash.copyFailed") : ""}
      </span>
    </span>
  );
}
