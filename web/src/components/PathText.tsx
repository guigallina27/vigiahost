import { Fragment } from "react";
import { useTranslation } from "react-i18next";
import { segmentHidden } from "../lib/text";

type Props = { path: string };

/**
 * Caminho de arquivo vindo do servidor analisado. Quebra em qualquer ponto sem estourar o layout
 * e mostra caracteres de controle e de direção de texto como escapes destacados, para que um nome
 * como "foto‮gpj.php" não se disfarce de "fotophp.jpg" (escopo, seção 14.2).
 */
export function PathText({ path }: Props) {
  const { t } = useTranslation();
  const segments = segmentHidden(path);
  const hasHidden = segments.some((s) => s.kind === "escape");
  return (
    <code dir="ltr" className="font-mono text-[0.9375em] [overflow-wrap:anywhere] [unicode-bidi:isolate]">
      {segments.map((s, i) =>
        s.kind === "escape" ? (
          <mark
            key={i}
            className="mx-px rounded-sm border border-current bg-(--vh-high-bg) px-0.5 text-(--vh-high-fg) not-italic"
          >
            {s.value}
          </mark>
        ) : (
          <Fragment key={i}>{withBreaks(s.value)}</Fragment>
        ),
      )}
      {hasHidden && <span className="visually-hidden"> ({t("path.escaped")})</span>}
    </code>
  );
}

// Oportunidade de quebra depois de cada barra, para caminhos longos quebrarem entre diretórios.
function withBreaks(text: string) {
  const parts = text.split("/");
  return parts.map((part, i) => (
    <Fragment key={i}>
      {part}
      {i < parts.length - 1 && (
        <>
          /<wbr />
        </>
      )}
    </Fragment>
  ));
}
