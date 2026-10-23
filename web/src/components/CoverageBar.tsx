import { useTranslation } from "react-i18next";
import { formatNumber, formatPercent } from "../lib/format";

type Props = {
  analyzed: number;
  eligible: number;
  /** Quantos ficaram de fora (limite de tamanho, permissão, erro); o detalhe dos motivos fica na tela de Cobertura. */
  skipped?: number;
  unit?: string;
};

/**
 * Cobertura como número principal ("99,8% de cobertura") e barra apenas ilustrativa:
 * a informação está no texto, e a barra fica fora da árvore de acessibilidade.
 */
export function CoverageBar({ analyzed, eligible, skipped, unit }: Props) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  if (eligible <= 0) return <p className="m-0 text-sm text-ink-muted">{t("coverage.empty")}</p>;
  const ratio = Math.min(1, Math.max(0, analyzed / eligible));
  const tone = ratio >= 0.99 ? "bg-(--vh-ok-fg)" : ratio >= 0.9 ? "bg-(--vh-medium-fg)" : "bg-(--vh-critical-fg)";
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <p className="m-0 text-lg font-bold tabular-nums">
        {t("coverage.value", { percent: formatPercent(analyzed, eligible, lng) })}
      </p>
      <div aria-hidden="true" className="h-2 overflow-clip rounded-full bg-sunken outline outline-1 -outline-offset-1 outline-line">
        <div className={`vh-meter-fill h-full rounded-full ${tone}`} style={{ inlineSize: `${ratio * 100}%` }} />
      </div>
      <p className="m-0 text-sm text-ink-muted tabular-nums">
        {t("coverage.detail", {
          analyzed: formatNumber(analyzed, lng),
          eligible: formatNumber(eligible, lng),
          unit: unit ?? t("coverage.unitFiles"),
        })}
        {skipped ? ` · ${t("coverage.skipped", { count: skipped, formatted: formatNumber(skipped, lng) })}` : ""}
      </p>
    </div>
  );
}
