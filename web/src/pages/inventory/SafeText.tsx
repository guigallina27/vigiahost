import { useTranslation } from "react-i18next";
import { segmentHidden } from "../../lib/text";

/**
 * Texto curto vindo do servidor analisado que não é caminho (nome do processo, usuário, unidade, detalhe):
 * caracteres de controle e de direção de texto aparecem como escapes destacados, como no PathText.
 */
export function SafeText({ text, mono = false }: { text: string; mono?: boolean }) {
  const { t } = useTranslation();
  const segments = segmentHidden(text);
  const hasHidden = segments.some((s) => s.kind === "escape");
  return (
    <span dir="ltr" className={`[overflow-wrap:anywhere] [unicode-bidi:isolate] ${mono ? "font-mono text-[0.9375em]" : ""}`}>
      {segments.map((s, i) =>
        s.kind === "escape" ? (
          <mark key={i} className="mx-px rounded-sm border border-current bg-(--vh-high-bg) px-0.5 text-(--vh-high-fg)">
            {s.value}
          </mark>
        ) : (
          <span key={i}>{s.value}</span>
        ),
      )}
      {hasHidden && <span className="visually-hidden"> ({t("path.escaped")})</span>}
    </span>
  );
}
