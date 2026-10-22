import { CircleCheck, CircleHelp, PackageCheck, PackageX, RotateCcw, TriangleAlert, Wrench } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useCurrentUser } from "../../auth/session";
import { Badge } from "../../components/Badge";
import { Panel } from "../../components/Panel";
import { PathText } from "../../components/PathText";
import { TableScroll } from "../../components/TableScroll";
import { Timestamp } from "../../components/Timestamp";
import { PageHeader } from "../../layout/PageHeader";
import { formatNumber } from "../../lib/format";
import { DetailItem } from "../findings/parts";
import { SafeText } from "../inventory/SafeText";
import { CheckButton, CheckStatus, Loading, ReportInfo, ReportNotes, ReportProblem, useReportRun } from "./SystemParts";
import {
  cacheState,
  expectedTools,
  isToolHint,
  sortUpdates,
  updateSeverity,
  updateSeverityEntries,
  updateTone,
  type PackageUpdate,
  type UpdatesReport,
} from "./systemFormat";
import { useSystemCheck, useUpdatesReport } from "./useSystemCheck";

/** Correções pendentes, serviços a reiniciar e reinício (rota /atualizacoes; ?execucao=<id> para um guardado). */
export function UpdatesPage() {
  const { t } = useTranslation();
  const runId = useReportRun();
  const check = useSystemCheck("updates");
  const q = useUpdatesReport(runId);
  const { canOperate } = useCurrentUser();
  const action = canOperate ? <CheckButton check={check} /> : null;

  return (
    <>
      <PageHeader title={t("system.updates.title")} subtitle={t("system.updates.subtitle")} actions={action} />
      <div className="flex min-w-0 flex-col gap-6">
        <CheckStatus check={check} />
        {q.isPending ? (
          <Loading />
        ) : q.isError ? (
          <ReportProblem kind="updates" icon={PackageCheck} error={q.error} runId={runId} retry={() => void q.refetch()} checkAction={action} />
        ) : (
          <UpdatesView report={q.data} />
        )}
      </div>
    </>
  );
}

export default UpdatesPage;

function UpdatesView({ report }: { report: UpdatesReport }) {
  const { t } = useTranslation();
  return (
    <>
      <ReportInfo kind="updates" report={report} />
      <ReportNotes error={report.error} warnings={report.warnings} />
      <div className="grid items-start gap-6 xl:grid-cols-2">
        <CachePanel report={report} />
        <RebootPanel report={report} />
      </div>
      <SecurityPanel report={report} />
      <ServicesPanel report={report} />
      <ToolsPanel report={report} />
      {report.other.length > 0 && (
        <Panel title={t("system.updates.other")}>
          <details>
            <summary className="inline-flex min-h-11 cursor-pointer items-center font-semibold text-accent">
              {t("system.updates.otherCount", { count: report.other.length })} · {t("system.updates.showOther")}
            </summary>
            <UpdatesTable list={report.other} caption={t("system.updates.otherCaption")} security={false} />
          </details>
        </Panel>
      )}
    </>
  );
}

function CachePanel({ report }: { report: UpdatesReport }) {
  const { t } = useTranslation();
  const state = cacheState(report);
  return (
    <Panel title={t("system.updates.cache")}>
      {state === "never" ? (
        <p className="m-0 flex gap-2">
          <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-(--vh-high-fg)" />
          <span>{t("system.updates.cacheNever")}</span>
        </p>
      ) : (
        <dl className="m-0 grid gap-3">
          <DetailItem label={t("system.updates.cacheUpdated")}>
            <Timestamp date={new Date(report.cache_updated_at ?? "")} />
          </DetailItem>
        </dl>
      )}
      {state === "stale" && (
        <p className="m-0 flex gap-2">
          <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-(--vh-high-fg)" />
          <span>{t("system.updates.cacheStale")}</span>
        </p>
      )}
      {report.refreshed && <p className="m-0">{t("system.updates.refreshed")}</p>}
      {report.refresh_error && <p className="m-0 [overflow-wrap:anywhere]">{t("system.updates.refreshError", { error: report.refresh_error })}</p>}
      {!report.refresh_allowed && <p className="m-0 max-w-prose text-sm text-ink-muted">{t("system.updates.refreshOff")}</p>}
    </Panel>
  );
}

function RebootPanel({ report }: { report: UpdatesReport }) {
  const { t } = useTranslation();
  const r = report.reboot;
  const badge = !r.known ? (
    <Badge tone="neutral" icon={CircleHelp} variant="outline">
      {t("system.updates.rebootUnknown")}
    </Badge>
  ) : r.required ? (
    <Badge tone="medium" icon={RotateCcw}>
      {t("system.updates.rebootRequired")}
    </Badge>
  ) : (
    <Badge tone="ok" icon={CircleCheck} variant="outline">
      {t("system.updates.rebootNotRequired")}
    </Badge>
  );
  return (
    <Panel title={t("system.updates.reboot")} actions={badge}>
      {!r.known && <p className="m-0 text-sm text-ink-muted">{t("system.updates.rebootUnknownHint")}</p>}
      <dl className="m-0 grid gap-3 sm:grid-cols-2">
        <DetailItem label={t("system.updates.runningKernel")}>
          <span className="font-mono">{r.running_kernel || "—"}</span>
        </DetailItem>
        {r.latest_kernel && (
          <DetailItem label={t("system.updates.latestKernel")}>
            <span className="font-mono">{r.latest_kernel}</span>
          </DetailItem>
        )}
        {r.reasons && r.reasons.length > 0 && (
          <DetailItem label={t("system.updates.reasons")}>
            <ul className="m-0 list-none p-0">
              {r.reasons.map((x) => (
                <li key={x}>{x}</li>
              ))}
            </ul>
          </DetailItem>
        )}
      </dl>
    </Panel>
  );
}

function SecurityPanel({ report }: { report: UpdatesReport }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const entries = updateSeverityEntries(report.by_severity);
  return (
    <Panel title={t("system.updates.security")}>
      {report.security.length === 0 ? (
        <p className="m-0 flex items-center gap-2">
          <CircleCheck aria-hidden="true" className="size-4 shrink-0 text-(--vh-ok-fg)" />
          {t("system.updates.securityEmpty")}
        </p>
      ) : (
        <>
          <ul aria-label={t("system.updates.colSeverity")} className="m-0 flex list-none flex-wrap gap-x-3 gap-y-1.5 p-0">
            {entries.map(([s, count]) => (
              <li key={s} className="inline-flex items-center gap-1.5">
                <Badge tone={updateTone(s)} icon={PackageX}>
                  {t(`system.updates.severity.${s}`)}
                </Badge>
                <span className="font-bold tabular-nums">{formatNumber(count, lng)}</span>
              </li>
            ))}
          </ul>
          <UpdatesTable list={sortUpdates(report.security)} caption={t("system.updates.securityCaption")} security />
        </>
      )}
    </Panel>
  );
}

function UpdatesTable({ list, caption, security }: { list: PackageUpdate[]; caption: string; security: boolean }) {
  const { t } = useTranslation();
  return (
    <TableScroll label={caption}>
      <table className="vh-table">
        <caption className="visually-hidden">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">{t("system.updates.colPackage")}</th>
            <th scope="col">{t("system.updates.colVersions")}</th>
            {security && <th scope="col">{t("system.updates.colSeverity")}</th>}
            {security && <th scope="col">{t("system.updates.colAdvisories")}</th>}
            <th scope="col">{t("system.updates.colRepo")}</th>
          </tr>
        </thead>
        <tbody>
          {list.map((u) => (
            <tr key={`${u.name}.${u.arch ?? ""}`}>
              <td className="min-w-40">
                <SafeText text={u.arch ? `${u.name}.${u.arch}` : u.name} mono />
              </td>
              <td className="min-w-56 font-mono text-sm [overflow-wrap:anywhere]">
                {u.installed ?? "—"} → {u.available}
              </td>
              {security && (
                <td>
                  <Badge tone={updateTone(u.severity)} icon={PackageX}>
                    {t(`system.updates.severity.${updateSeverity(u.severity)}`)}
                  </Badge>
                </td>
              )}
              {security && (
                <td className="min-w-48 text-sm">
                  <span className="flex flex-col gap-0.5">
                    {(u.advisories ?? []).length > 0 && <span className="font-mono [overflow-wrap:anywhere]">{(u.advisories ?? []).join(", ")}</span>}
                    <span className="text-ink-muted">{t("system.updates.cves", { count: (u.cves ?? []).length })}</span>
                  </span>
                </td>
              )}
              <td className="min-w-32 text-sm [overflow-wrap:anywhere]">{u.repo ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableScroll>
  );
}

function ServicesPanel({ report }: { report: UpdatesReport }) {
  const { t } = useTranslation();
  return (
    <Panel title={t("system.updates.services")}>
      {report.services.length === 0 ? (
        <p className="m-0 flex items-center gap-2">
          <CircleCheck aria-hidden="true" className="size-4 shrink-0 text-(--vh-ok-fg)" />
          {t("system.updates.servicesEmpty")}
        </p>
      ) : (
        <TableScroll label={t("system.updates.servicesCaption")}>
          <table className="vh-table">
            <caption className="visually-hidden">{t("system.updates.servicesCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("system.updates.colUnit")}</th>
                <th scope="col">{t("system.updates.colPids")}</th>
                <th scope="col">{t("system.updates.colFiles")}</th>
                <th scope="col">{t("system.updates.colSource")}</th>
              </tr>
            </thead>
            <tbody>
              {report.services.map((s) => (
                <tr key={s.unit}>
                  <td className="min-w-40">
                    <SafeText text={s.unit} mono />
                  </td>
                  <td className="font-mono text-sm [overflow-wrap:anywhere]">{(s.pids ?? []).join(", ") || "—"}</td>
                  <td className="min-w-56">
                    <FileList files={s.files ?? []} />
                  </td>
                  <td className="font-mono text-sm">{s.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
      )}
      {report.processes.length > 0 && (
        <>
          <h3 className="m-0 text-base font-semibold">{t("system.updates.processes")}</h3>
          <TableScroll label={t("system.updates.processesCaption")}>
            <table className="vh-table">
              <caption className="visually-hidden">{t("system.updates.processesCaption")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("system.updates.colPid")}</th>
                  <th scope="col">{t("system.updates.colComm")}</th>
                  <th scope="col">{t("system.updates.colUid")}</th>
                  <th scope="col">{t("system.updates.colFiles")}</th>
                </tr>
              </thead>
              <tbody>
                {report.processes.map((p) => (
                  <tr key={p.pid}>
                    <td className="tabular-nums">{p.pid}</td>
                    <td>
                      <SafeText text={p.comm} />
                    </td>
                    <td className="tabular-nums">{p.uid}</td>
                    <td className="min-w-56">
                      <FileList files={p.files} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
        </>
      )}
    </Panel>
  );
}

function FileList({ files }: { files: string[] }) {
  if (files.length === 0) return <>—</>;
  return (
    <ul className="m-0 flex list-none flex-col gap-0.5 p-0 text-sm">
      {files.map((f) => (
        <li key={f}>
          <PathText path={f} />
        </li>
      ))}
    </ul>
  );
}

function ToolsPanel({ report }: { report: UpdatesReport }) {
  const { t } = useTranslation();
  const tools = expectedTools(report.manager);
  if (tools.length === 0) return null;
  return (
    <Panel title={t("system.updates.tools")}>
      <ul className="m-0 flex list-none flex-col gap-3 p-0">
        {tools.map(({ name }) => {
          const present = report.tools[name] === true;
          return (
            <li key={name} className="flex min-w-0 flex-col gap-1">
              <span className="flex flex-wrap items-center gap-2">
                <code className="font-semibold">{name}</code>
                {present ? (
                  <Badge tone="ok" icon={CircleCheck} variant="outline">
                    {t("system.toolPresent")}
                  </Badge>
                ) : (
                  <Badge tone="neutral" icon={Wrench} variant="outline">
                    {t("system.toolMissing")}
                  </Badge>
                )}
              </span>
              {!present && isToolHint(name) && <span className="text-sm text-ink-muted">{t(`system.updates.toolHint.${name}`)}</span>}
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}
