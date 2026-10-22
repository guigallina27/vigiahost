import { useInfiniteQuery } from "@tanstack/react-query";
import { FilterX, ListChecks, Play, RefreshCw, SearchX } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";
import { api, unwrap } from "../../api/client";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { SelectField } from "../../components/Field";
import { PathText } from "../../components/PathText";
import { Timestamp } from "../../components/Timestamp";
import { useCurrentUser } from "../../auth/session";
import { PageHeader } from "../../layout/PageHeader";
import { formatNumber, formatPercent } from "../../lib/format";
import { AccountFilterChip } from "../accounts/AccountParts";
import { NewRunDialog } from "./NewRunDialog";
import { DurationText, KindLabel, OriginText, PhaseText, RunStatus } from "./RunBits";
import {
  filtersFromSearch,
  filtersToQuery,
  isActive,
  RUN_KINDS,
  STATUS_GROUP_KEYS,
  toDate,
  type Run,
  type RunFilters,
} from "./runFormat";
import { TableScroll } from "../../components/TableScroll";

const PAGE_SIZE = 50;

/** Lista de execuções (rota /execucoes), com filtros no endereço e paginação por cursor. */
export function RunsPage() {
  const { t } = useTranslation();
  const { canOperate } = useCurrentUser();
  const [params, setParams] = useSearchParams();
  const [dialogOpen, setDialogOpen] = useState(false);
  const filters = filtersFromSearch(params);
  const query = filtersToQuery(filters);
  const filtered = Object.keys(query).length > 0;

  const runs = useInfiniteQuery({
    queryKey: ["runs", query],
    queryFn: ({ pageParam, signal }) =>
      unwrap(
        api.GET("/api/v1/runs", {
          params: { query: { ...query, limit: PAGE_SIZE, ...(pageParam ? { before: pageParam } : {}) } },
          signal,
        }),
      ),
    initialPageParam: "",
    getNextPageParam: (last) => last.next_before || undefined,
  });

  function setFilter(key: keyof RunFilters, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  const list = runs.data?.pages.flatMap((p) => p.runs) ?? [];
  const newRun = canOperate && (
    <Button variant="primary" onClick={() => setDialogOpen(true)}>
      <Play aria-hidden="true" className="size-4" />
      {t("runs.newRun")}
    </Button>
  );

  return (
    <>
      <PageHeader title={t("runs.title")} subtitle={t("runs.subtitle")} actions={newRun} />
      <div className="flex flex-col gap-5">
        <form role="search" aria-label={t("runs.filters.legend")} onSubmit={(e) => e.preventDefault()} className="flex flex-wrap items-end gap-3">
          <SelectField
            label={t("runs.filters.status")}
            className="w-full sm:w-64"
            value={filters.status ?? ""}
            onChange={(e) => setFilter("status", e.target.value)}
            options={[
              { value: "", label: t("runs.filters.allStatus") },
              ...STATUS_GROUP_KEYS.map((g) => ({ value: g, label: t(`runs.filters.${g}`) })),
            ]}
          />
          <SelectField
            label={t("runs.filters.kind")}
            className="w-full sm:w-52"
            value={filters.kind ?? ""}
            onChange={(e) => setFilter("kind", e.target.value)}
            options={[
              { value: "", label: t("runs.filters.allKinds") },
              ...RUN_KINDS.map((k) => ({ value: k, label: t(`runs.kind.${k}`) })),
            ]}
          />
          {filters.account !== undefined && (
            <div className="flex min-h-11 items-center">
              <AccountFilterChip uid={filters.account} onRemove={() => setFilter("account", "")} />
            </div>
          )}
          {filtered && (
            <Button variant="ghost" onClick={() => setParams(new URLSearchParams(), { replace: true })}>
              <FilterX aria-hidden="true" className="size-4" />
              {t("runs.filters.clear")}
            </Button>
          )}
        </form>

        {runs.isPending ? (
          <p className="m-0 text-ink-muted" role="status">
            {t("states.loading")}
          </p>
        ) : runs.isError && list.length === 0 ? (
          <EmptyState
            tone="error"
            icon={ListChecks}
            title={t("runs.loadError")}
            description={runs.error.message}
            action={
              <Button onClick={() => void runs.refetch()} disabled={runs.isFetching}>
                <RefreshCw aria-hidden="true" className="size-4" />
                {t("states.retry")}
              </Button>
            }
          />
        ) : list.length === 0 ? (
          filtered ? (
            <EmptyState
              icon={SearchX}
              title={t("runs.empty.filteredTitle")}
              description={t("runs.empty.filteredDescription")}
              action={
                <Button onClick={() => setParams(new URLSearchParams(), { replace: true })}>
                  <FilterX aria-hidden="true" className="size-4" />
                  {t("runs.filters.clear")}
                </Button>
              }
            />
          ) : (
            <EmptyState
              icon={ListChecks}
              title={t("runs.empty.title")}
              description={canOperate ? t("runs.empty.description") : t("runs.empty.readerDescription")}
              action={
                canOperate && (
                  <Button variant="primary" onClick={() => setDialogOpen(true)}>
                    <Play aria-hidden="true" className="size-4" />
                    {t("runs.firstRun")}
                  </Button>
                )
              }
            />
          )
        ) : (
          <>
            <RunsTable runs={list} />
            {runs.isError && (
              <p role="alert" className="m-0 rounded-control bg-(--vh-critical-bg) p-3 text-sm text-(--vh-critical-fg)">
                {runs.error.message}
              </p>
            )}
            {runs.hasNextPage && (
              <div>
                <Button onClick={() => void runs.fetchNextPage()} disabled={runs.isFetchingNextPage}>
                  {runs.isFetchingNextPage ? t("runs.loadingMore") : t("runs.loadMore")}
                </Button>
              </div>
            )}
          </>
        )}
      </div>
      <NewRunDialog open={dialogOpen} onClose={() => setDialogOpen(false)} />
    </>
  );
}

function RunsTable({ runs }: { runs: Run[] }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  return (
    <TableScroll label={t("runs.table.caption")}>
      <table className="vh-table">
        <caption className="visually-hidden">{t("runs.table.caption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("runs.table.run")}</th>
            <th scope="col">{t("runs.table.status")}</th>
            <th scope="col">{t("runs.table.kind")}</th>
            <th scope="col">{t("runs.table.origin")}</th>
            <th scope="col">{t("runs.table.started")}</th>
            <th scope="col">{t("runs.table.duration")}</th>
            <th scope="col" className="text-end">
              {t("runs.table.findings")}
            </th>
            <th scope="col">{t("runs.table.processed")}</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => {
            const started = toDate(run.started_at);
            const created = toDate(run.created_at);
            const extra = run.paths.length - 1;
            return (
              <tr key={run.id}>
                <td className="min-w-44">
                  <Link to={`/execucoes/${encodeURIComponent(run.id)}`} className="font-mono font-semibold [overflow-wrap:anywhere]">
                    {run.id}
                  </Link>
                  {created && (
                    <span className="block">
                      <Timestamp date={created} compact />
                    </span>
                  )}
                </td>
                <td className="min-w-36">
                  <RunStatus run={run} />
                  {isActive(run.status) && run.phase && (
                    <span className="mt-1 block text-sm text-ink-muted">
                      <PhaseText phase={run.phase} />
                    </span>
                  )}
                </td>
                <td className="min-w-48">
                  <KindLabel kind={run.kind} />
                  <span className="mt-1 block text-sm">
                    {run.kind === "processes" ? (
                      <span className="text-ink-muted">{t("runs.table.allProcesses")}</span>
                    ) : run.paths.length === 0 ? (
                      <span className="text-ink-muted">{t("runs.none")}</span>
                    ) : (
                      <>
                        <PathText path={run.paths[0] ?? ""} />
                        {extra > 0 && <span className="text-ink-muted"> {t("runs.table.morePaths", { count: extra })}</span>}
                      </>
                    )}
                  </span>
                  {run.accounts && run.accounts.length > 0 && (
                    <span className="mt-1 block text-sm text-ink-muted">
                      {t("accounts.runCoverage.count", { count: run.accounts.length, formatted: formatNumber(run.accounts.length, lng) })}
                    </span>
                  )}
                </td>
                <td className="min-w-28">
                  <OriginText run={run} />
                </td>
                <td className="min-w-40">
                  {started ? <Timestamp date={started} compact /> : <span className="text-ink-muted">{t("runs.table.notStarted")}</span>}
                </td>
                <td className="whitespace-nowrap">
                  <DurationText run={run} />
                </td>
                <td className={`text-end tabular-nums ${run.findings_count > 0 ? "font-bold" : ""}`}>
                  {formatNumber(run.findings_count, lng)}
                </td>
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
                    <span className="text-ink-muted">{t("runs.none")}</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </TableScroll>
  );
}
