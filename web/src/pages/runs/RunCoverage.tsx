import { CircleCheck, CircleX, FlaskConical, FlaskConicalOff } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { Schemas } from "../../api/client";
import { Badge } from "../../components/Badge";
import { CoverageBar } from "../../components/CoverageBar";
import { formatNumber } from "../../lib/format";
import { formatBytes, formatDuration, isKnownSkipReason, SKIP_REASONS, skipEntries, skippedTotal } from "./runFormat";
import { TableScroll } from "../../components/TableScroll";
import { formatBytes as formatBinary, formatDecimal } from "../config/units";

type EngineCoverage = Schemas["EngineCoverage"];

const ENGINE_NAMES: Record<string, string> = { "yara-x": "YARA-X", clamav: "ClamAV" };

export function engineName(id: string): string {
  return ENGINE_NAMES[id] ?? id;
}

/** Nome e explicação de um motivo de exclusão, inclusive para motivos que esta versão do painel não conhece. */
export function useSkipReasonText() {
  const { t } = useTranslation();
  return (reason: string) =>
    isKnownSkipReason(reason)
      ? { label: t(`runs.skip.${reason}.label`), description: t(`runs.skip.${reason}.description`) }
      : { label: t("runs.skip.unknownLabel", { reason }), description: t("runs.skip.unknownDescription") };
}

/** Motivos de itens fora da análise, com contagem e explicação em linguagem simples. */
export function SkipReasonTable({ skipped, caption }: { skipped: Record<string, number> | undefined; caption?: string }) {
  const { t, i18n } = useTranslation();
  const text = useSkipReasonText();
  const entries = skipEntries(skipped);
  if (entries.length === 0) return null;
  return (
    <TableScroll label={caption ?? t("runs.engine.skipCaption")}>
      <table className="vh-table">
        <caption className="visually-hidden">{caption ?? t("runs.engine.skipCaption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("runs.engine.reason")}</th>
            <th scope="col" className="text-end">
              {t("runs.engine.count")}
            </th>
            <th scope="col">{t("runs.engine.meaning")}</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => {
            const { label, description } = text(e.reason);
            return (
              <tr key={e.reason}>
                <td className="font-semibold">{label}</td>
                <td className="text-end tabular-nums">{formatNumber(e.count, i18n.language)}</td>
                <td className="min-w-48 text-ink-muted">{description}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </TableScroll>
  );
}

/** Glossário com todos os motivos conhecidos (tela de Cobertura). */
export function SkipReasonGlossary() {
  const text = useSkipReasonText();
  return (
    <dl className="m-0 grid gap-3 sm:grid-cols-2">
      {SKIP_REASONS.map((reason) => {
        const { label, description } = text(reason);
        return (
          <div key={reason} className="grid min-w-0 gap-0.5">
            <dt className="font-semibold">{label}</dt>
            <dd className="m-0 text-sm text-ink-muted">{description}</dd>
          </div>
        );
      })}
    </dl>
  );
}

/** Cobertura de um motor numa execução: versões, autoteste, analisados/elegíveis e motivos de exclusão. */
export function EngineCoverageCard({ engine }: { engine: EngineCoverage }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const errors = Object.entries(engine.errors ?? {}).filter(([, n]) => n > 0);
  return (
    <article className="flex min-w-0 flex-col gap-3 rounded-panel border border-line bg-surface p-4">
      <div className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-1">
        <h3 className="m-0 text-base font-bold break-words">{engineName(engine.engine)}</h3>
        {engine.version && <span className="font-mono text-sm text-ink-muted [overflow-wrap:anywhere]">{engine.version}</span>}
      </div>
      <dl className="m-0 grid grid-cols-[auto_minmax(0,1fr)] items-center gap-x-3 gap-y-1.5 text-sm">
        <dt className="text-ink-muted">{t("runs.engine.state")}</dt>
        <dd className="m-0">
          {engine.available ? (
            <Badge tone="ok" icon={CircleCheck} variant="outline">
              {t("runs.engine.available")}
            </Badge>
          ) : (
            <Badge tone="critical" icon={CircleX} variant="outline">
              {t("runs.engine.unavailable")}
            </Badge>
          )}
        </dd>
        <dt className="text-ink-muted">{t("runs.engine.selftest")}</dt>
        <dd className="m-0 flex min-w-0 flex-wrap items-center gap-2">
          {engine.selftest_passed ? (
            <Badge tone="ok" icon={FlaskConical} variant="outline">
              {t("runs.engine.selftestPassed")}
            </Badge>
          ) : (
            <Badge tone="critical" icon={FlaskConicalOff} variant="outline">
              {t("runs.engine.selftestFailed")}
            </Badge>
          )}
          {engine.selftest_detail && <span className="min-w-0 text-ink-muted break-words">{engine.selftest_detail}</span>}
        </dd>
        {engine.rules_version && (
          <>
            <dt className="text-ink-muted">{t("runs.engine.rules")}</dt>
            <dd className="m-0 min-w-0 font-mono [overflow-wrap:anywhere]">{engine.rules_version}</dd>
          </>
        )}
        <dt className="text-ink-muted">{t("runs.engine.volume")}</dt>
        <dd className="m-0 tabular-nums">{formatBytes(engine.bytes_analyzed, lng)}</dd>
        <dt className="text-ink-muted">{t("runs.engine.time")}</dt>
        <dd className="m-0 tabular-nums">{formatDuration(engine.seconds, lng)}</dd>
        {engine.files_per_second !== undefined && engine.mb_per_second !== undefined && (
          <>
            <dt className="text-ink-muted">{t("runs.engine.throughput")}</dt>
            <dd className="m-0 tabular-nums">
              {t("runs.engine.throughputValue", {
                files: formatDecimal(engine.files_per_second, lng),
                volume: formatBinary(engine.mb_per_second * (1 << 20), lng),
              })}
            </dd>
          </>
        )}
      </dl>
      <CoverageBar analyzed={engine.analyzed} eligible={engine.eligible} skipped={skippedTotal(engine.skipped)} />
      {engine.from_cache > 0 && (
        <p className="m-0 text-sm text-ink-muted">
          {t("runs.engine.fromCache", { count: engine.from_cache, formatted: formatNumber(engine.from_cache, lng) })}
        </p>
      )}
      {engine.error && (
        <p className="m-0 rounded-control bg-(--vh-critical-bg) p-2 text-sm text-(--vh-critical-fg) [overflow-wrap:anywhere]">
          {engine.error}
        </p>
      )}
      {skipEntries(engine.skipped).length > 0 && (
        <div className="flex min-w-0 flex-col gap-2">
          <h4 className="m-0 text-sm font-semibold">{t("runs.engine.skippedTitle")}</h4>
          <SkipReasonTable skipped={engine.skipped} />
        </div>
      )}
      {errors.length > 0 && (
        <div className="flex min-w-0 flex-col gap-2">
          <h4 className="m-0 text-sm font-semibold">{t("runs.engine.errorsTitle")}</h4>
          <TableScroll label={t("runs.engine.errorsCaption")}>
            <table className="vh-table">
              <caption className="visually-hidden">{t("runs.engine.errorsCaption")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("runs.engine.errorMessage")}</th>
                  <th scope="col" className="text-end">
                    {t("runs.engine.errorCount")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {errors.map(([message, count]) => (
                  <tr key={message}>
                    <td className="min-w-48 font-mono text-[0.8125rem] [overflow-wrap:anywhere]">{message}</td>
                    <td className="text-end tabular-nums">{formatNumber(count, lng)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
        </div>
      )}
    </article>
  );
}
