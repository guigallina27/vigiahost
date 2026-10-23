import { CircleCheck, FileCheck, ShieldAlert } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useCurrentUser } from "../../auth/session";
import { Badge } from "../../components/Badge";
import { Panel } from "../../components/Panel";
import { PathText } from "../../components/PathText";
import { SeverityBadge } from "../../components/SeverityBadge";
import { SeverityCounts } from "../../components/SeverityCounts";
import { TableScroll } from "../../components/TableScroll";
import { PageHeader } from "../../layout/PageHeader";
import { formatNumber } from "../../lib/format";
import { DetailItem } from "../findings/parts";
import { SafeText } from "../inventory/SafeText";
import { CheckButton, CheckStatus, Loading, ReportInfo, ReportNotes, ReportProblem, useReportRun } from "./SystemParts";
import {
  ignoredEntries,
  isChange,
  packageText,
  severityCounts,
  type IntegrityFile,
  type IntegrityReport,
} from "./systemFormat";
import { useIntegrityReport, useSystemCheck } from "./useSystemCheck";

/** Verificação contra os pacotes (rota /integridade; ?execucao=<id> mostra um relatório guardado). */
export function IntegrityPage() {
  const { t } = useTranslation();
  const runId = useReportRun();
  const check = useSystemCheck("integrity");
  const q = useIntegrityReport(runId);
  const { canOperate } = useCurrentUser();
  const action = canOperate ? <CheckButton check={check} /> : null;

  return (
    <>
      <PageHeader title={t("system.integrity.title")} subtitle={t("system.integrity.subtitle")} actions={action} />
      <div className="flex min-w-0 flex-col gap-6">
        <CheckStatus check={check} />
        {q.isPending ? (
          <Loading />
        ) : q.isError ? (
          <ReportProblem
            kind="integrity"
            icon={FileCheck}
            error={q.error}
            runId={runId}
            retry={() => void q.refetch()}
            checkAction={action}
          />
        ) : (
          <IntegrityView report={q.data} />
        )}
      </div>
    </>
  );
}

export default IntegrityPage;

function IntegrityView({ report }: { report: IntegrityReport }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const n = (v: number) => <span className="tabular-nums">{formatNumber(v, lng)}</span>;
  const ignored = ignoredEntries(report.ignored);
  const counts = severityCounts(report.by_severity);

  return (
    <>
      <ReportInfo kind="integrity" report={report} />
      <ReportNotes error={report.error} warnings={report.warnings} />

      <div className="grid items-start gap-6 xl:grid-cols-2">
        <Panel title={t("system.integrity.summary")}>
          <dl className="m-0 grid gap-4 sm:grid-cols-2">
            <DetailItem label={t("system.integrity.manager")}>
              {report.manager ? <span className="font-mono">{report.manager}</span> : t("system.integrity.managerNone")}
            </DetailItem>
            <DetailItem label={t("system.integrity.packages")}>{n(report.packages)}</DetailItem>
            <DetailItem label={t("system.integrity.differences")}>{n(report.differences)}</DetailItem>
            <DetailItem label={t("system.integrity.listed")}>{n(counts.total)}</DetailItem>
            <DetailItem label={t("system.integrity.ignored")}>
              {ignored.length === 0 ? (
                t("system.integrity.ignoredNone")
              ) : (
                <ul className="m-0 list-none p-0">
                  {ignored.map(([reason, count]) => (
                    <li key={reason}>
                      {n(count)} {t(`system.integrity.ignoredReason.${reason}`)}
                    </li>
                  ))}
                </ul>
              )}
            </DetailItem>
            <DetailItem label={t("system.integrity.tools")}>
              {report.tools.length === 0 ? "—" : <span className="font-mono">{report.tools.join(", ")}</span>}
            </DetailItem>
          </dl>
          {report.manager === "dpkg" && !report.debsums_available && (
            <p className="m-0 rounded-control border border-line-strong bg-sunken p-3 text-sm">{t("system.integrity.debsumsMissing")}</p>
          )}
        </Panel>

        <Panel title={t("system.integrity.bySeverity")}>
          <SeverityCounts
            counts={counts}
            layout="grid"
            hrefFor={(s) => `/achados?category=integrity&severity=${s}`}
          />
        </Panel>
      </div>

      <Panel title={t("system.integrity.files")}>
        {report.files.length === 0 ? (
          <p className="m-0 flex items-center gap-2">
            <CircleCheck aria-hidden="true" className="size-4 shrink-0 text-(--vh-ok-fg)" />
            {t("system.integrity.filesEmpty")}
          </p>
        ) : (
          <FilesTable files={report.files} />
        )}
        {(report.truncated ?? 0) > 0 && (
          <p className="m-0 text-sm text-ink-muted">
            {t("system.integrity.truncated", { shown: formatNumber(report.files.length, lng), count: report.truncated ?? 0 })}
          </p>
        )}
      </Panel>

      <SignaturesPanel report={report} />
    </>
  );
}

function FilesTable({ files }: { files: IntegrityFile[] }) {
  const { t } = useTranslation();
  return (
    <TableScroll label={t("system.integrity.filesCaption")}>
      <table className="vh-table">
        <caption className="visually-hidden">{t("system.integrity.filesCaption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("system.integrity.colFile")}</th>
            <th scope="col">{t("system.integrity.colPackage")}</th>
            <th scope="col">{t("system.integrity.colChanges")}</th>
            <th scope="col">{t("system.integrity.colSeverity")}</th>
          </tr>
        </thead>
        <tbody>
          {files.map((f) => (
            <tr key={f.path}>
              <td className="min-w-64">
                <span className="flex min-w-0 flex-col gap-0.5">
                  <PathText path={f.path} />
                  <span className="text-sm text-ink-muted">
                    {t(`system.integrity.class.${f.class}`)}
                    {f.config && ` · ${t("system.integrity.config")}`}
                  </span>
                </span>
              </td>
              <td className="min-w-40">
                {f.packages && f.packages.length > 0 ? (
                  <span className="flex flex-col gap-0.5">
                    {f.packages.map((p) => (
                      <SafeText key={packageText(p)} text={packageText(p)} mono />
                    ))}
                  </span>
                ) : (
                  "—"
                )}
              </td>
              <td className="min-w-48">
                <span className="flex min-w-0 flex-col gap-1">
                  <span>{f.changes.filter(isChange).map((c) => t(`system.integrity.change.${c}`)).join(", ")}</span>
                  <code className="text-sm text-ink-muted">{f.flags}</code>
                  {(f.expected || f.actual) && (
                    <details className="text-sm">
                      <summary className="inline-flex min-h-11 cursor-pointer items-center font-semibold text-accent">
                        {t("system.integrity.expected")}
                      </summary>
                      <dl className="m-0 grid gap-1">
                        {f.expected && (
                          <DetailItem label={`${t("system.integrity.expected")} (${f.algo ?? ""})`}>
                            <code className="[overflow-wrap:anywhere]">{f.expected}</code>
                          </DetailItem>
                        )}
                        {f.actual && (
                          <DetailItem label={t("system.integrity.actual")}>
                            <code className="[overflow-wrap:anywhere]">{f.actual}</code>
                          </DetailItem>
                        )}
                      </dl>
                    </details>
                  )}
                </span>
              </td>
              <td>
                <SeverityBadge severity={f.severity} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableScroll>
  );
}

function SignaturesPanel({ report }: { report: IntegrityReport }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const sig = report.signatures;
  if (!sig) {
    return (
      <Panel title={t("system.integrity.signatures")}>
        <p className="m-0">{report.signature_error ? t("system.integrity.signatureError", { error: report.signature_error }) : "—"}</p>
      </Panel>
    );
  }
  const unsigned = sig.unsigned ?? [];
  const unknown = sig.unknown_key ?? [];
  const keys = sig.keys ?? [];
  return (
    <Panel title={t("system.integrity.signatures")}>
      <p className="m-0 max-w-prose">{t(sig.method === "package" ? "system.integrity.methodPackage" : "system.integrity.methodRepository")}</p>
      <dl className="m-0 grid gap-4 sm:grid-cols-2">
        {sig.method === "package" && (
          <DetailItem label={t("system.integrity.signed")}>
            <span className="tabular-nums">{formatNumber(sig.signed, lng)}</span>
          </DetailItem>
        )}
        {sig.method === "package" && (
          <DetailItem label={t("system.integrity.unsigned")}>
            <PackageList list={unsigned.map(packageText)} />
          </DetailItem>
        )}
        {sig.method === "package" && (
          <DetailItem label={t("system.integrity.unknownKey")}>
            <PackageList list={unknown.map((p) => `${packageText(p)} (${p.key_id})`)} />
          </DetailItem>
        )}
        {keys.length > 0 && (
          <DetailItem label={t("system.integrity.keys")}>
            <ul className="m-0 list-none p-0">
              {keys.map((k) => (
                <li key={k.id}>
                  <code>{k.id}</code> <SafeText text={k.summary} />
                </li>
              ))}
            </ul>
          </DetailItem>
        )}
      </dl>
      {sig.repos.length > 0 && (
        <TableScroll label={t("system.integrity.reposCaption")}>
          <table className="vh-table">
            <caption className="visually-hidden">{t("system.integrity.reposCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("system.integrity.colRepo")}</th>
                <th scope="col">{t("system.integrity.colConf")}</th>
                <th scope="col">{t("system.integrity.colEnabled")}</th>
                <th scope="col">{t("system.integrity.colVerified")}</th>
              </tr>
            </thead>
            <tbody>
              {sig.repos.map((r) => (
                <tr key={`${r.file}:${r.id}`}>
                  <td className="min-w-48">
                    <span className="flex min-w-0 flex-col gap-0.5">
                      <SafeText text={r.id} mono />
                      {r.name && <span className="text-sm text-ink-muted"><SafeText text={r.name} /></span>}
                    </span>
                  </td>
                  <td className="min-w-48">
                    <PathText path={r.file} />
                  </td>
                  <td>{t(r.enabled ? "system.integrity.yes" : "system.integrity.no")}</td>
                  <td>
                    {r.problem ? (
                      <Badge tone="high" icon={ShieldAlert}>
                        {t(`system.integrity.problem.${r.problem}`)}
                      </Badge>
                    ) : r.verified ? (
                      <Badge tone="ok" icon={CircleCheck} variant="outline">
                        {t("system.integrity.verified")}
                      </Badge>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
      )}
    </Panel>
  );
}

function PackageList({ list }: { list: string[] }) {
  const { t } = useTranslation();
  if (list.length === 0) return <>{t("system.integrity.none")}</>;
  return (
    <ul className="m-0 list-none p-0">
      {list.map((p) => (
        <li key={p}>
          <SafeText text={p} mono />
        </li>
      ))}
    </ul>
  );
}
