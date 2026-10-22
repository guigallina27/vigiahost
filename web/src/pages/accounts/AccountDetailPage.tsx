import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, CircleAlert, FileQuestion, RefreshCw, ScanSearch, ServerCrash, ShieldCheck } from "lucide-react";
import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";
import { api, ApiError, unwrap } from "../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { Panel } from "../../components/Panel";
import { PathText } from "../../components/PathText";
import { SeverityBadge } from "../../components/SeverityBadge";
import { SeverityCounts } from "../../components/SeverityCounts";
import { StatusBadge } from "../../components/StatusBadge";
import { TableScroll } from "../../components/TableScroll";
import { Timestamp } from "../../components/Timestamp";
import { PageHeader } from "../../layout/PageHeader";
import { formatNumber, formatPercent } from "../../lib/format";
import { openStates } from "../findings/filters";
import { FindingObject } from "../findings/parts";
import { KindLabel as PersistenceKindLabel } from "../inventory/PersistenceView";
import { ProcessTable } from "../inventory/ProcessTable";
import { SafeText } from "../inventory/SafeText";
import { newIdempotencyKey, toDate } from "../runs/runFormat";
import {
  accountFindingsHref,
  accountRunsHref,
  isExecutorUnavailable,
  parseUid,
  persistenceOf,
  processesOf,
  type Account,
} from "./accounts";
import { HomeWarning, LastRunCell, ScanAccountsDialog, type ScanRequest } from "./AccountParts";
import { accountQuery } from "./queries";

const FINDINGS_LIMIT = 50;
const RUNS_LIMIT = 10;

/** Não insiste em 4xx (inventário inexistente responde 404): a tela explica o que falta. */
function retry(count: number, err: Error): boolean {
  return !(err instanceof ApiError && err.status !== undefined && err.status < 500) && count < 2;
}

/** Detalhe da conta (rota /contas/:uid): identificação, risco, última verificação e o que a conta tem no servidor. */
export function AccountDetailPage() {
  const { t } = useTranslation();
  const params = useParams();
  const uid = parseUid(params.uid);
  const account = useQuery({ ...accountQuery(uid ?? 0), enabled: uid !== undefined });
  const fallbackTitle = t("accounts.detail.titleUid", { uid: params.uid ?? "" });

  if (uid === undefined || (account.isError && account.error instanceof ApiError && account.error.status === 404)) {
    return (
      <>
        <PageHeader title={fallbackTitle} actions={<BackLink />} />
        <EmptyState
          icon={FileQuestion}
          title={t("accounts.detail.notFoundTitle")}
          description={t("accounts.detail.notFoundDescription", { uid: params.uid ?? "" })}
          action={<BackLink />}
        />
      </>
    );
  }
  if (account.isPending) {
    return (
      <>
        <PageHeader title={fallbackTitle} actions={<BackLink />} />
        <p className="m-0 text-ink-muted" role="status">
          {t("states.loading")}
        </p>
      </>
    );
  }
  if (account.isError) {
    const executor = isExecutorUnavailable(account.error);
    return (
      <>
        <PageHeader title={fallbackTitle} actions={<BackLink />} />
        <EmptyState
          tone="error"
          icon={executor ? ServerCrash : CircleAlert}
          title={executor ? t("accounts.errors.executorTitle") : t("accounts.detail.loadError")}
          description={
            <div role="alert" className="flex flex-col gap-2">
              <p className="m-0">{executor ? t("accounts.errors.executorDescription") : account.error.message}</p>
              {executor && (
                <p className="m-0">
                  {t("accounts.errors.executorAction")} <code className="font-mono">systemctl status vigiahost-executor</code>
                </p>
              )}
            </div>
          }
          action={
            <Button onClick={() => void account.refetch()} disabled={account.isFetching}>
              <RefreshCw aria-hidden="true" className="size-4" />
              {t("states.retry")}
            </Button>
          }
        />
      </>
    );
  }
  return <AccountView account={account.data} />;
}

export default AccountDetailPage;

function BackLink() {
  const { t } = useTranslation();
  return (
    <Link to="/contas" className="inline-flex min-h-11 items-center gap-2 font-semibold">
      <ArrowLeft aria-hidden="true" className="size-4" />
      {t("accounts.detail.back")}
    </Link>
  );
}

function Item({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid min-w-0 gap-0.5">
      <dt className="text-sm text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 font-semibold break-words">{children}</dd>
    </div>
  );
}

function AccountView({ account: a }: { account: Account }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const { canOperate } = useCurrentUser();
  const [scan, setScan] = useState<ScanRequest | null>(null);

  const actions = (
    <div className="flex flex-wrap items-center gap-3">
      <BackLink />
      {canOperate && (
        <Button
          variant="primary"
          onClick={() => setScan({ target: { kind: "uids", uids: [a.uid] }, accounts: [a], key: newIdempotencyKey() })}
        >
          <ScanSearch aria-hidden="true" className="size-4" />
          {t("accounts.scanOne")}
        </Button>
      )}
    </div>
  );

  return (
    <>
      <PageHeader
        title={t("accounts.detail.title", { name: a.name })}
        subtitle={`${t("accounts.uid", { uid: a.uid })} · ${a.system ? t("accounts.kind.system") : t("accounts.kind.hosting")}`}
        actions={actions}
      />
      <div className="flex min-w-0 flex-col gap-6">
        <div className="grid items-start gap-6 xl:grid-cols-2">
          <Panel title={t("accounts.detail.identity")}>
            <dl className="m-0 grid gap-4 sm:grid-cols-2">
              <Item label={t("accounts.detail.name")}>
                <SafeText text={a.name} />
              </Item>
              <Item label={t("accounts.detail.uid")}>
                <span className="tabular-nums">{a.uid}</span>
              </Item>
              <Item label={t("accounts.detail.home")}>
                <PathText path={a.home} />
                {!a.home_ok && <HomeWarning />}
              </Item>
              <Item label={t("accounts.detail.shell")}>{a.shell ? <PathText path={a.shell} /> : t("runs.none")}</Item>
              <Item label={t("accounts.detail.kind")}>
                {a.system ? t("accounts.kind.system") : t("accounts.kind.hosting")}
                <span className="block text-sm font-normal text-ink-muted">
                  {a.system ? t("accounts.kind.systemHint") : t("accounts.kind.hostingHint")}
                </span>
              </Item>
            </dl>
          </Panel>

          <Panel title={t("accounts.detail.lastRun")}>
            <LastRunCell account={a} />
            <Link to={accountRunsHref(a.uid)} className="inline-flex min-h-11 items-center self-start font-semibold">
              {t("accounts.detail.allRuns")}
            </Link>
          </Panel>
        </div>

        <Panel
          title={t("accounts.detail.openFindings")}
          actions={
            <Link to={accountFindingsHref(a.uid)} className="inline-flex min-h-11 items-center font-semibold">
              {t("accounts.detail.viewAllFindings")}
            </Link>
          }
        >
          <p className="m-0 text-2xl font-bold tabular-nums">
            {t("accounts.detail.openTotal", { count: a.open_findings.total, formatted: formatNumber(a.open_findings.total, lng) })}
          </p>
          <SeverityCounts counts={a.open_findings} layout="grid" hrefFor={(s) => accountFindingsHref(a.uid, s)} />
          <AccountFindings uid={a.uid} total={a.open_findings.total} />
        </Panel>

        <AccountRuns uid={a.uid} />

        <div className="grid items-start gap-6">
          <AccountProcesses account={a} />
          <AccountPersistence account={a} />
        </div>

        <Panel title={t("accounts.detail.exceptions")}>
          <p className="m-0 flex items-start gap-2">
            <ShieldCheck aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-accent" />
            <span>{t("accounts.detail.exceptionsHint")}</span>
          </p>
          <Link to="/excecoes" className="inline-flex min-h-11 items-center self-start font-semibold">
            {t("accounts.detail.viewExceptions")}
          </Link>
        </Panel>
      </div>
      <ScanAccountsDialog request={scan} onClose={() => setScan(null)} />
    </>
  );
}

function Loading() {
  const { t } = useTranslation();
  return (
    <p role="status" className="m-0 text-ink-muted">
      {t("states.loading")}
    </p>
  );
}

function ErrorLine({ message }: { message: string }) {
  return (
    <p role="alert" className="m-0 rounded-control bg-(--vh-critical-bg) p-3 text-sm text-(--vh-critical-fg)">
      {message}
    </p>
  );
}

/** Até 50 achados abertos da conta; o resto fica na lista de achados filtrada. */
function AccountFindings({ uid, total }: { uid: number; total: number }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const q = useQuery({
    // Chave própria: a lista de achados usa ["findings", consulta] com páginas (outra forma de dado).
    queryKey: ["findings", "account-preview", uid],
    queryFn: ({ signal }) =>
      unwrap(api.GET("/api/v1/findings", { params: { query: { account: uid, state: openStates, limit: FINDINGS_LIMIT } }, signal })),
    retry,
  });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorLine message={t("accounts.detail.findingsError", { cause: q.error.message })} />;
  const rows = q.data.findings;
  if (rows.length === 0) return <p className="m-0 text-ink-muted">{t("accounts.detail.noFindings")}</p>;
  return (
    <div className="flex min-w-0 flex-col gap-2">
      <TableScroll label={t("accounts.detail.findingsCaption")}>
        <table className="vh-table">
          <caption className="visually-hidden">{t("accounts.detail.findingsCaption")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("findings.table.severity")}</th>
              <th scope="col">{t("findings.table.state")}</th>
              <th scope="col">{t("findings.table.signature")}</th>
              <th scope="col">{t("findings.table.object")}</th>
              <th scope="col">{t("findings.table.lastSeen")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <tr key={f.id}>
                <td>
                  <SeverityBadge severity={f.severity} />
                </td>
                <td>
                  <StatusBadge kind="finding" state={f.state} />
                </td>
                <td className="min-w-48">
                  <Link to={`/achados/${f.id}`} className="font-semibold [overflow-wrap:anywhere]">
                    {f.signature}
                  </Link>
                  <span className="block text-sm text-ink-muted">{t(`findings.kind.${f.kind}`)}</span>
                </td>
                <td className="min-w-56">
                  <FindingObject finding={f} />
                </td>
                <td className="min-w-40">
                  <Timestamp date={new Date(f.last_seen)} compact />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>
      {(q.data.next_before !== undefined || total > rows.length) && (
        <p className="m-0 text-sm text-ink-muted">
          {t("accounts.detail.findingsShown", { shown: formatNumber(rows.length, lng) })}{" "}
          <Link to={accountFindingsHref(uid)} className="font-semibold">
            {t("accounts.detail.viewAllFindings")}
          </Link>
        </p>
      )}
    </div>
  );
}

function AccountRuns({ uid }: { uid: number }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const q = useQuery({
    queryKey: ["runs", "account-preview", uid],
    queryFn: ({ signal }) => unwrap(api.GET("/api/v1/runs", { params: { query: { account: uid, limit: RUNS_LIMIT } }, signal })),
    retry,
  });
  return (
    <Panel
      title={t("accounts.detail.runs")}
      actions={
        <Link to={accountRunsHref(uid)} className="inline-flex min-h-11 items-center font-semibold">
          {t("accounts.detail.allRuns")}
        </Link>
      }
    >
      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorLine message={t("accounts.detail.runsError", { cause: q.error.message })} />
      ) : q.data.runs.length === 0 ? (
        <p className="m-0 text-ink-muted">{t("accounts.detail.noRuns")}</p>
      ) : (
        <TableScroll label={t("accounts.detail.runsCaption")}>
          <table className="vh-table">
            <caption className="visually-hidden">{t("accounts.detail.runsCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("runs.table.run")}</th>
                <th scope="col">{t("runs.table.status")}</th>
                <th scope="col">{t("runs.table.started")}</th>
                <th scope="col" className="text-end">
                  {t("runs.table.findings")}
                </th>
                <th scope="col">{t("runs.table.processed")}</th>
              </tr>
            </thead>
            <tbody>
              {q.data.runs.map((run) => {
                const when = toDate(run.started_at) ?? toDate(run.created_at);
                return (
                  <tr key={run.id}>
                    <td className="min-w-44">
                      <Link to={`/execucoes/${encodeURIComponent(run.id)}`} className="font-mono font-semibold [overflow-wrap:anywhere]">
                        {run.id}
                      </Link>
                    </td>
                    <td>
                      <StatusBadge kind="run" state={run.status} />
                    </td>
                    <td className="min-w-40">{when ? <Timestamp date={when} compact /> : t("runs.none")}</td>
                    <td className="text-end tabular-nums">{formatNumber(run.findings_count, lng)}</td>
                    <td className="min-w-32 tabular-nums">
                      {run.files_eligible > 0 ? (
                        <>
                          <span className="font-semibold">{formatPercent(run.files_processed, run.files_eligible, lng)}</span>
                          <span className="block text-sm text-ink-muted">
                            {t("runs.table.processedOf", {
                              processed: formatNumber(run.files_processed, lng),
                              eligible: formatNumber(run.files_eligible, lng),
                            })}
                          </span>
                        </>
                      ) : (
                        t("runs.none")
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableScroll>
      )}
    </Panel>
  );
}

/** Sem inspeção de processos ainda (404): explica e leva ao inventário. */
function NoSnapshot() {
  const { t } = useTranslation();
  return (
    <p className="m-0 text-ink-muted">
      {t("accounts.detail.noSnapshot")}{" "}
      <Link to="/processos" className="font-semibold">
        {t("accounts.openInventory")}
      </Link>
    </p>
  );
}

function SnapshotLine({ runId, takenAt }: { runId: string; takenAt: string }) {
  const { t } = useTranslation();
  return (
    <p className="m-0 flex flex-wrap items-baseline gap-x-2 gap-y-1 text-sm text-ink-muted">
      <span>{t("inventory.snapshotOf")}</span>
      <Link to={`/execucoes/${encodeURIComponent(runId)}`} className="font-mono font-semibold">
        {runId}
      </Link>
      <span aria-hidden="true">·</span>
      <Timestamp date={new Date(takenAt)} compact />
    </p>
  );
}

function AccountProcesses({ account }: { account: Account }) {
  const { t } = useTranslation();
  const q = useQuery({
    queryKey: ["inventory", "processes", "latest"],
    queryFn: ({ signal }) => unwrap(api.GET("/api/v1/inventory/processes", { params: { query: {} }, signal })),
    retry,
  });
  const notFound = q.isError && q.error instanceof ApiError && q.error.status === 404;
  const list = q.data ? processesOf(account, q.data.processes) : [];
  return (
    <Panel title={t("accounts.detail.processes")}>
      {q.isPending ? (
        <Loading />
      ) : notFound ? (
        <NoSnapshot />
      ) : q.isError ? (
        <ErrorLine message={t("accounts.detail.inventoryError", { cause: q.error.message })} />
      ) : (
        <>
          <SnapshotLine runId={q.data.run_id} takenAt={q.data.taken_at} />
          {list.length === 0 ? (
            <p className="m-0 text-ink-muted">{t("accounts.detail.noProcesses")}</p>
          ) : (
            <ProcessTable processes={list} />
          )}
        </>
      )}
    </Panel>
  );
}

function AccountPersistence({ account }: { account: Account }) {
  const { t } = useTranslation();
  const q = useQuery({
    queryKey: ["inventory", "persistence", "latest"],
    queryFn: ({ signal }) => unwrap(api.GET("/api/v1/inventory/persistence", { params: { query: {} }, signal })),
    retry,
  });
  const notFound = q.isError && q.error instanceof ApiError && q.error.status === 404;
  const list = q.data ? persistenceOf(account, q.data.items) : [];
  return (
    <Panel title={t("accounts.detail.persistence")}>
      {q.isPending ? (
        <Loading />
      ) : notFound ? (
        <NoSnapshot />
      ) : q.isError ? (
        <ErrorLine message={t("accounts.detail.inventoryError", { cause: q.error.message })} />
      ) : (
        <>
          <SnapshotLine runId={q.data.run_id} takenAt={q.data.taken_at} />
          <p className="m-0 text-sm text-ink-muted">{t("accounts.detail.persistenceHint")}</p>
          {list.length === 0 ? (
            <p className="m-0 text-ink-muted">{t("accounts.detail.noPersistence")}</p>
          ) : (
            <TableScroll label={t("accounts.detail.persistenceCaption")}>
              <table className="vh-table">
                <caption className="visually-hidden">{t("accounts.detail.persistenceCaption")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("accounts.detail.colKind")}</th>
                    <th scope="col">{t("accounts.detail.colPath")}</th>
                    <th scope="col">{t("accounts.detail.colDetail")}</th>
                    <th scope="col">{t("accounts.detail.colOwner")}</th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((e) => (
                    <tr key={`${e.kind}:${e.path}`}>
                      <td className="min-w-36">
                        <PersistenceKindLabel kind={e.kind} />
                      </td>
                      <td className="min-w-56">
                        <PathText path={e.path} />
                      </td>
                      <td className="min-w-56">{e.detail ? <SafeText text={e.detail} mono /> : t("runs.none")}</td>
                      <td>{e.owner ? <SafeText text={e.owner} /> : t("runs.none")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableScroll>
          )}
        </>
      )}
    </Panel>
  );
}
