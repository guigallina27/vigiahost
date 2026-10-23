import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { formatNumber } from "../lib/format";
import { SeverityBadge, severities, type Severity } from "./SeverityBadge";

export type SeverityCountsValue = Record<Severity, number> & { total: number };

type Props = {
  counts: SeverityCountsValue;
  /**
   * inline: só as severidades com achados, lado a lado (células de tabela);
   * grid: todas as severidades com o número, em cartões (painéis de resumo).
   */
  layout?: "inline" | "grid";
  /** Endereço da lista filtrada por severidade; com ele, cada cartão do grid vira link. */
  hrefFor?: (severity: Severity) => string;
};

/** Achados abertos por severidade: selo (ícone + texto) seguido da quantidade; nunca só cor. */
export function SeverityCounts({ counts, layout = "inline", hrefFor }: Props) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;

  if (layout === "inline") {
    if (counts.total === 0) return <span className="text-ink-muted">{t("severityCounts.none")}</span>;
    return (
      <ul aria-label={t("severityCounts.label")} className="m-0 flex list-none flex-wrap gap-x-3 gap-y-1.5 p-0">
        {severities
          .filter((s) => counts[s] > 0)
          .map((s) => (
            <li key={s} className="inline-flex items-center gap-1.5">
              <SeverityBadge severity={s} />
              <span className="font-bold tabular-nums">{formatNumber(counts[s], lng)}</span>
            </li>
          ))}
      </ul>
    );
  }

  const cell = "flex min-h-11 items-center justify-between gap-2 rounded-control border border-line px-3 py-2";
  return (
    <ul aria-label={t("severityCounts.label")} className="m-0 grid list-none grid-cols-[repeat(auto-fill,minmax(9.5rem,1fr))] gap-2 p-0">
      {severities.map((s) => {
        const content = (
          <>
            <SeverityBadge severity={s} />
            <span className="text-lg font-bold tabular-nums">{formatNumber(counts[s], lng)}</span>
          </>
        );
        return (
          <li key={s} className="min-w-0">
            {hrefFor ? (
              <Link to={hrefFor(s)} className={`${cell} text-ink no-underline hover:border-line-strong hover:bg-sunken`}>
                {content}
              </Link>
            ) : (
              <span className={cell}>{content}</span>
            )}
          </li>
        );
      })}
    </ul>
  );
}
