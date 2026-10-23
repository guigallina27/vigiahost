import { useQuery } from "@tanstack/react-query";
import { Gauge, Pause, Snail } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import type { Schemas } from "../../api/client";
import { Badge } from "../../components/Badge";
import { Panel } from "../../components/Panel";
import { StatusBadge } from "../../components/StatusBadge";
import { TableScroll } from "../../components/TableScroll";
import { Timestamp } from "../../components/Timestamp";
import { formatNumber } from "../../lib/format";
import { formatBytes as formatBinary, formatDecimal, formatPercentValue } from "../config/units";
import { PhaseText, useProfileLabel } from "./RunBits";
import { comparisonQuery } from "./queries";
import { phaseShares, throttleOutcome } from "./performance";
import { formatDuration, isActive, toDate, type Run } from "./runFormat";

const MIB = 1 << 20;

function Item({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <div className="grid min-w-0 gap-0.5">
      <dt className="text-sm text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 font-semibold break-words tabular-nums">{children}</dd>
      {hint && <dd className="m-0 text-sm text-ink-muted">{hint}</dd>}
    </div>
  );
}

/** Nome do recurso de pressão no idioma ativo (cpu, io, memory). */
export function useResourceName() {
  const { t } = useTranslation();
  return (r: string) => (r === "cpu" || r === "io" || r === "memory" ? t(`runs.resource.${r}`) : r);
}

/** Aviso, durante a execução, de que o ritmo está reduzido ou pausado pela pressão do servidor. */
export function ThrottleNote({ run }: { run: Run }) {
  const { t, i18n } = useTranslation();
  const resource = useResourceName();
  const th = run.throttle;
  if (!th || run.status !== "running") return null;
  const pressure = formatPercentValue(th.pressure, i18n.language);
  const paused = th.state === "paused";
  return (
    <p role="status" className="m-0 flex items-start gap-2 rounded-control border border-(--vh-medium-fg) bg-(--vh-medium-bg) p-3 text-(--vh-medium-fg)">
      {paused ? <Pause aria-hidden="true" className="mt-0.5 size-4 shrink-0" /> : <Snail aria-hidden="true" className="mt-0.5 size-4 shrink-0" />}
      <span className="min-w-0">
        {paused
          ? t("runs.detail.throttlePaused", { resource: resource(th.resource), pressure })
          : t("runs.detail.throttleReduced", { resource: resource(th.resource), pressure, count: th.workers })}
      </span>
    </p>
  );
}

/** Medidas de desempenho da execução terminada: vazão, CPU, memória, etapas e limitação por pressão. */
export function PerformancePanel({ run }: { run: Run }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const m = run.summary?.metrics;
  const sum = run.summary;
  if (!m || !sum) {
    return (
      <Panel title={t("runs.performance.title")}>
        <p className="m-0 text-ink-muted">{isActive(run.status) ? t("runs.performance.empty") : t("runs.performance.emptyOld")}</p>
      </Panel>
    );
  }
  const files = run.kind === "files";
  const sourceKey =
    m.source === "cgroup" ? "runs.performance.sourceCgroup" : m.source === "rusage" ? "runs.performance.sourceRusage" : "runs.performance.sourceNone";
  return (
    <Panel title={t("runs.performance.title")}>
      <dl className="m-0 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {files && (
          <>
            <Item label={t("runs.performance.filesPerSecond")}>{formatDecimal(sum.files_per_second, lng)}</Item>
            <Item label={t("runs.performance.mbPerSecond")}>
              {t("runs.performance.perSecond", { value: formatBinary(sum.mb_per_second * MIB, lng) })}
            </Item>
            <Item label={t("runs.performance.bytesRead")} hint={t("runs.performance.bytesReadHint")}>
              {formatBinary(m.bytes_read, lng)}
            </Item>
          </>
        )}
        <Item label={t("runs.performance.cpu")}>{formatDuration(m.cpu_seconds, lng)}</Item>
        {files && m.cpu_seconds_per_gb !== undefined && (
          <Item label={t("runs.performance.cpuPerGb")}>{t("runs.performance.secondsValue", { value: formatDecimal(m.cpu_seconds_per_gb, lng) })}</Item>
        )}
        <Item label={t("runs.performance.memoryPeak")}>{m.memory_peak_bytes > 0 ? formatBinary(m.memory_peak_bytes, lng) : t("runs.none")}</Item>
        {files && (
          <Item label={t("runs.performance.limited")}>
            {t("runs.performance.limitedValue", {
              limited: formatDuration(m.throttle.limited_seconds, lng),
              paused: formatDuration(m.throttle.paused_seconds, lng),
            })}
          </Item>
        )}
      </dl>
      <p className="m-0 text-sm text-ink-muted">{t(sourceKey)}</p>
      <PhasesTable phases={m.phases} />
      {files && <ThrottleSection metrics={m} />}
    </Panel>
  );
}

function PhasesTable({ phases }: { phases: Schemas["PhaseTiming"][] }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  if (phases.length === 0) return null;
  const rows = phaseShares(phases);
  const pct = new Intl.NumberFormat(lng, { style: "percent", maximumFractionDigits: 0 });
  return (
    <div className="flex min-w-0 flex-col gap-2">
      <h3 className="m-0 text-base font-semibold">{t("runs.performance.phasesTitle")}</h3>
      <TableScroll label={t("runs.performance.phasesCaption")}>
        <table className="vh-table">
          <caption className="visually-hidden">{t("runs.performance.phasesCaption")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("runs.performance.phase")}</th>
              <th scope="col" className="text-end">
                {t("runs.performance.time")}
              </th>
              <th scope="col" className="text-end">
                {t("runs.performance.share")}
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.phase}>
                <td>
                  <PhaseText phase={r.phase} />
                </td>
                <td className="text-end tabular-nums">{formatDuration(r.seconds, lng)}</td>
                <td className="text-end tabular-nums">{pct.format(r.share)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>
    </div>
  );
}

function ThrottleSection({ metrics }: { metrics: Schemas["RunMetrics"] }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const resource = useResourceName();
  const outcome = throttleOutcome(metrics);
  const events = metrics.throttle.events;
  return (
    <div className="flex min-w-0 flex-col gap-2">
      <h3 className="m-0 text-base font-semibold">{t("runs.performance.throttleTitle")}</h3>
      {outcome !== "limited" && <p className="m-0 text-ink-muted">{t(`runs.performance.throttle.${outcome}`)}</p>}
      {events.length > 0 && (
        <TableScroll label={t("runs.performance.eventsCaption")}>
          <table className="vh-table">
            <caption className="visually-hidden">{t("runs.performance.eventsCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("runs.performance.eventAt")}</th>
                <th scope="col">{t("runs.performance.eventAction")}</th>
                <th scope="col">{t("runs.performance.eventResource")}</th>
                <th scope="col" className="text-end">
                  {t("runs.performance.eventPressure")}
                </th>
                <th scope="col" className="text-end">
                  {t("runs.performance.eventThreshold")}
                </th>
                <th scope="col" className="text-end">
                  {t("runs.performance.eventWorkers")}
                </th>
              </tr>
            </thead>
            <tbody>
              {events.map((e, i) => {
                const at = toDate(e.at);
                return (
                  <tr key={`${e.at}-${i}`}>
                    <td>{at ? <Timestamp date={at} /> : e.at}</td>
                    <td>{t(`runs.performance.action.${e.action}`)}</td>
                    <td>{resource(e.resource)}</td>
                    <td className="text-end tabular-nums">{formatPercentValue(e.pressure, lng)}</td>
                    <td className="text-end tabular-nums">{formatPercentValue(e.threshold, lng)}</td>
                    <td className="text-end tabular-nums">{formatNumber(e.workers, lng)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableScroll>
      )}
      {metrics.throttle.events_dropped > 0 && (
        <p className="m-0 text-sm text-ink-muted">
          {t("runs.performance.eventsDropped", { count: metrics.throttle.events_dropped, formatted: formatNumber(metrics.throttle.events_dropped, lng) })}
        </p>
      )}
    </div>
  );
}

/** Ajustes de limites feitos durante a execução (quem, quando, antes e depois). */
export function AdjustmentsPanel({ run }: { run: Run }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const list = run.adjustments ?? [];
  if (list.length === 0) return null;
  const pair = (before: string, after: string) => (before === after ? <span className="text-ink-muted">{after}</span> : t("runs.adjustments.change", { before, after }));
  const bw = (v: number) => (v > 0 ? t("runs.performance.perSecond", { value: formatBinary(v, lng) }) : t("runs.adjustments.noBandwidth"));
  return (
    <Panel title={t("runs.adjustments.title")}>
      <TableScroll label={t("runs.adjustments.caption")}>
        <table className="vh-table">
          <caption className="visually-hidden">{t("runs.adjustments.caption")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("runs.adjustments.at")}</th>
              <th scope="col">{t("runs.adjustments.actor")}</th>
              <th scope="col">{t("runs.adjustments.cpu")}</th>
              <th scope="col">{t("runs.adjustments.memory")}</th>
              <th scope="col">{t("runs.adjustments.ioRead")}</th>
              <th scope="col">{t("runs.adjustments.ioWeight")}</th>
            </tr>
          </thead>
          <tbody>
            {[...list].reverse().map((a, i) => {
              const at = toDate(a.at);
              return (
                <tr key={`${a.at}-${i}`}>
                  <td>{at ? <Timestamp date={at} /> : a.at}</td>
                  <td className="break-words">{a.actor}</td>
                  <td className="tabular-nums">{pair(`${a.before.cpu_quota_percent}%`, `${a.after.cpu_quota_percent}%`)}</td>
                  <td className="tabular-nums">{pair(formatBinary(a.before.memory_max_bytes, lng), formatBinary(a.after.memory_max_bytes, lng))}</td>
                  <td className="tabular-nums">{pair(bw(a.before.io_read_bytes_per_sec), bw(a.after.io_read_bytes_per_sec))}</td>
                  <td className="tabular-nums">{pair(String(a.before.io_weight), String(a.after.io_weight))}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableScroll>
    </Panel>
  );
}

/** Desempenho desta execução ao lado das últimas terminadas do mesmo tipo. */
export function ComparisonPanel({ run }: { run: Run }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const profileLabel = useProfileLabel();
  const q = useQuery(comparisonQuery(run.id, run.status));
  const optional = (v: number | undefined, fmt: (n: number) => string) => (v === undefined ? <span className="text-ink-muted">—</span> : fmt(v));
  return (
    <Panel title={t("runs.comparison.title")}>
      <p className="m-0 text-sm text-ink-muted">{t("runs.comparison.intro")}</p>
      {q.isPending ? (
        <p role="status" className="m-0 text-ink-muted">
          {t("states.loading")}
        </p>
      ) : q.isError ? (
        <p role="alert" className="m-0 [overflow-wrap:anywhere]">
          {t("runs.comparison.loadError", { cause: q.error.message })}
        </p>
      ) : q.data.runs.filter((r) => !r.current).length === 0 ? (
        <p className="m-0 text-ink-muted">{t("runs.comparison.empty")}</p>
      ) : (
        <TableScroll label={t("runs.comparison.caption")}>
          <table className="vh-table">
            <caption className="visually-hidden">{t("runs.comparison.caption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("runs.comparison.run")}</th>
                <th scope="col">{t("runs.comparison.status")}</th>
                <th scope="col">{t("runs.comparison.profile")}</th>
                <th scope="col" className="text-end">
                  {t("runs.comparison.duration")}
                </th>
                {run.kind === "files" && (
                  <>
                    <th scope="col" className="text-end">
                      {t("runs.comparison.filesPerSecond")}
                    </th>
                    <th scope="col" className="text-end">
                      {t("runs.comparison.mbPerSecond")}
                    </th>
                  </>
                )}
                <th scope="col" className="text-end">
                  {t("runs.comparison.cpu")}
                </th>
                <th scope="col" className="text-end">
                  {t("runs.comparison.memory")}
                </th>
                {run.kind === "files" && (
                  <th scope="col" className="text-end">
                    {t("runs.comparison.limited")}
                  </th>
                )}
                <th scope="col" className="text-end">
                  {t("runs.comparison.findings")}
                </th>
              </tr>
            </thead>
            <tbody>
              {q.data.runs.map((r) => (
                <tr key={r.id} aria-current={r.current ? "true" : undefined} className={r.current ? "bg-accent-soft" : undefined}>
                  <th scope="row" className="font-normal">
                    <span className="flex min-w-0 flex-wrap items-center gap-2">
                      {r.current ? (
                        <span className="font-mono text-sm [overflow-wrap:anywhere]">{r.id}</span>
                      ) : (
                        <Link to={`/execucoes/${r.id}`} className="inline-flex min-h-11 items-center font-mono text-sm [overflow-wrap:anywhere]">
                          {r.id}
                        </Link>
                      )}
                      {r.current && (
                        <Badge tone="neutral" icon={Gauge} variant="outline">
                          {t("runs.comparison.current")}
                        </Badge>
                      )}
                    </span>
                  </th>
                  <td>
                    <StatusBadge kind="run" state={r.status} />
                  </td>
                  <td>{profileLabel(r.profile)}</td>
                  <td className="text-end tabular-nums">{r.duration_seconds > 0 ? formatDuration(r.duration_seconds, lng) : "—"}</td>
                  {run.kind === "files" && (
                    <>
                      <td className="text-end tabular-nums">{formatDecimal(r.files_per_second, lng)}</td>
                      <td className="text-end tabular-nums">{formatBinary(r.mb_per_second * MIB, lng)}</td>
                    </>
                  )}
                  <td className="text-end tabular-nums">{optional(r.cpu_seconds, (v) => formatDuration(v, lng))}</td>
                  <td className="text-end tabular-nums">{optional(r.memory_peak_bytes, (v) => formatBinary(v, lng))}</td>
                  {run.kind === "files" && (
                    <td className="text-end tabular-nums">{optional(r.limited_seconds, (v) => formatDuration(v, lng))}</td>
                  )}
                  <td className="text-end tabular-nums">{formatNumber(r.findings, lng)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
      )}
    </Panel>
  );
}
