import { useTranslation } from "react-i18next";
import { formatAbsolute, formatRelative, formatZoneName } from "../lib/format";

type Props = {
  date: Date;
  /** Fuso do servidor; sem ele, usa o do navegador. */
  timeZone?: string;
  /** Uma linha só (para tabelas e cartões). */
  compact?: boolean;
  now?: Date;
};

/** Data relativa sempre acompanhada do horário absoluto e do fuso (escopo, seção 14.2). */
export function Timestamp({ date, timeZone, compact = false, now }: Props) {
  const { i18n, t } = useTranslation();
  if (Number.isNaN(date.getTime())) return <span>{t("time.unknown")}</span>;
  const lng = i18n.language;
  const relative = formatRelative(date, lng, now);
  const absolute = `${formatAbsolute(date, lng, timeZone)} ${formatZoneName(date, lng, timeZone)}`;
  return (
    <time dateTime={date.toISOString()} className={compact ? "text-sm" : "inline-flex flex-col"}>
      <span>{relative}</span>
      <span className={`text-ink-muted tabular-nums ${compact ? "" : "text-sm"}`}>
        {compact ? ` · ${absolute}` : absolute}
      </span>
    </time>
  );
}
