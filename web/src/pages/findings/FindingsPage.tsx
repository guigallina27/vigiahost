import { useInfiniteQuery } from "@tanstack/react-query";
import { FilterX, PlugZap, RefreshCw, ScanSearch, Search } from "lucide-react";
import { useId, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link, useLocation, useSearchParams } from "react-router";
import { api, unwrap } from "../../api/client";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { Field } from "../../components/Field";
import { SeverityBadge } from "../../components/SeverityBadge";
import { StatusBadge } from "../../components/StatusBadge";
import { Timestamp } from "../../components/Timestamp";
import { PageHeader } from "../../layout/PageHeader";
import { formatNumber } from "../../lib/format";
import {
  filtersToParams,
  filtersToQuery,
  findingStateList,
  hasActiveFilters,
  kindList,
  openStates,
  parseFilters,
  severityList,
  splitCategories,
  toggleValue,
  type FindingFilters,
} from "./filters";
import { FindingObject } from "./parts";

/** Lista de achados (rota sugerida: /achados). Filtros na URL; paginação por cursor com "Carregar mais". */
export function FindingsPage() {
  const { t, i18n } = useTranslation();
  const [params, setParams] = useSearchParams();
  const location = useLocation();
  const filters = parseFilters(params);
  const baseQuery = filtersToQuery(filters);

  const query = useInfiniteQuery({
    queryKey: ["findings", baseQuery],
    queryFn: ({ pageParam, signal }) =>
      unwrap(api.GET("/api/v1/findings", { params: { query: filtersToQuery(filters, pageParam) }, signal })),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => last.next_before,
  });

  const setFilters = (next: FindingFilters) => setParams(filtersToParams(next));
  const rows = query.data?.pages.flatMap((p) => p.findings) ?? [];
  const filtered = hasActiveFilters(filters);

  return (
    <>
      <PageHeader title={t("findings.title")} subtitle={t("findings.subtitle")} />

      <div className="flex flex-col gap-6">
        <FiltersForm filters={filters} onChange={setFilters} />

        {query.isPending ? (
          <p className="m-0 text-ink-muted" role="status">
            {t("states.loading")}
          </p>
        ) : query.isError && rows.length === 0 ? (
          <EmptyState
            tone="error"
            icon={PlugZap}
            title={t("findings.errorTitle")}
            description={<p className="m-0" role="alert">{query.error.message}</p>}
            action={
              <Button variant="primary" onClick={() => void query.refetch()} disabled={query.isFetching}>
                <RefreshCw aria-hidden="true" className="size-4" />
                {t("states.retry")}
              </Button>
            }
          />
        ) : rows.length === 0 ? (
          filtered ? (
            <EmptyState
              icon={FilterX}
              title={t("findings.emptyFilteredTitle")}
              description={t("findings.emptyFilteredDescription")}
              action={
                <Button onClick={() => setParams(new URLSearchParams())}>
                  <FilterX aria-hidden="true" className="size-4" />
                  {t("findings.filters.clear")}
                </Button>
              }
            />
          ) : (
            <EmptyState
              icon={ScanSearch}
              title={t("findings.emptyOpenTitle")}
              description={t("findings.emptyOpenDescription")}
              action={
                <Button onClick={() => setFilters({ ...filters, states: [] })}>{t("findings.filters.allStates")}</Button>
              }
            />
          )
        ) : (
          <div className="flex flex-col gap-3">
            <p className="m-0 text-sm text-ink-muted" role="status">
              {t("findings.loaded", { count: rows.length, formatted: formatNumber(rows.length, i18n.language) })}
            </p>
            <div className="vh-table-wrap">
              <table className="vh-table">
                <caption className="visually-hidden">{t("findings.table.caption")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("findings.table.severity")}</th>
                    <th scope="col">{t("findings.table.state")}</th>
                    <th scope="col">{t("findings.table.signature")}</th>
                    <th scope="col">{t("findings.table.object")}</th>
                    <th scope="col" className="text-end">
                      {t("findings.table.copies")}
                    </th>
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
                        <Link
                          to={`/achados/${f.id}`}
                          state={{ fromSearch: location.search }}
                          className="font-semibold text-accent underline underline-offset-4 [overflow-wrap:anywhere]"
                        >
                          {f.signature}
                        </Link>
                        <span className="block text-sm text-ink-muted [overflow-wrap:anywhere]">
                          {f.engine}
                          {f.category && ` · ${f.category}`}
                          {` · ${t(`findings.kind.${f.kind}`)}`}
                        </span>
                      </td>
                      <td className="min-w-56">
                        <FindingObject finding={f} />
                      </td>
                      <td className="text-end tabular-nums">{formatNumber(f.locations_count, i18n.language)}</td>
                      <td className="min-w-40">
                        <Timestamp date={new Date(f.last_seen)} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex flex-col items-start gap-2">
              {query.hasNextPage ? (
                <Button onClick={() => void query.fetchNextPage()} disabled={query.isFetchingNextPage}>
                  {query.isFetchingNextPage ? t("findings.loadingMore") : t("findings.loadMore")}
                </Button>
              ) : (
                <p className="m-0 text-sm text-ink-muted">{t("findings.endOfList")}</p>
              )}
              {query.isFetchNextPageError && (
                <p role="alert" className="m-0 rounded-control bg-(--vh-critical-bg) p-2 text-sm text-(--vh-critical-fg)">
                  {t("findings.loadMoreError", { cause: query.error?.message ?? "" })}
                </p>
              )}
            </div>
          </div>
        )}
      </div>
    </>
  );
}

const checkLabel =
  "flex min-h-11 cursor-pointer items-center gap-2 rounded-control border border-line-strong bg-surface px-3 py-1.5 has-checked:border-accent has-checked:bg-accent-soft has-focus-visible:outline-3 has-focus-visible:outline-offset-2 has-focus-visible:outline-(--vh-focus)";

function CheckGroup<T extends string>(props: {
  legend: string;
  hint?: string;
  values: readonly T[];
  selected: T[];
  label: (v: T) => string;
  onToggle: (v: T) => void;
}) {
  const hintId = useId();
  return (
    <fieldset className="m-0 min-w-0 border-0 p-0" aria-describedby={props.hint ? hintId : undefined}>
      <legend className="mb-1 p-0 font-semibold">{props.legend}</legend>
      {props.hint && (
        <p id={hintId} className="m-0 mb-2 text-sm text-ink-muted">
          {props.hint}
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        {props.values.map((v) => (
          <label key={v} className={checkLabel}>
            <input
              type="checkbox"
              checked={props.selected.includes(v)}
              onChange={() => props.onToggle(v)}
              className="size-4 shrink-0 focus-visible:outline-none"
            />
            <span className="min-w-0">{props.label(v)}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

function FiltersForm({ filters, onChange }: { filters: FindingFilters; onChange: (f: FindingFilters) => void }) {
  const { t } = useTranslation();
  const titleId = useId();
  const onlyOpen = filters.states.length === openStates.length && openStates.every((s) => filters.states.includes(s));

  // Campos de texto controlados, ressincronizados quando a URL muda (Voltar, Limpar, links da visão geral).
  const fromUrl = { q: filters.q, category: filters.categories.join(", "), run: filters.runId };
  const urlKey = JSON.stringify(fromUrl);
  const [text, setText] = useState(fromUrl);
  const [syncedKey, setSyncedKey] = useState(urlKey);
  if (syncedKey !== urlKey) {
    setSyncedKey(urlKey);
    setText(fromUrl);
  }

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    onChange({ ...filters, q: text.q.trim(), categories: splitCategories(text.category), runId: text.run.trim() });
  }

  return (
    <section
      aria-labelledby={titleId}
      className="flex min-w-0 flex-col gap-4 rounded-panel border border-line bg-surface p-5 shadow-panel"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 id={titleId} className="vh-label m-0 text-ink-muted">
          {t("findings.filters.title")}
        </h2>
        {hasActiveFilters(filters) && (
          <Button variant="ghost" onClick={() => onChange(parseFilters(new URLSearchParams()))}>
            <FilterX aria-hidden="true" className="size-4" />
            {t("findings.filters.clear")}
          </Button>
        )}
      </div>

      <form onSubmit={submit} className="grid items-end gap-3 md:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)_auto]">
        <Field
          label={t("findings.filters.search")}
          hint={t("findings.filters.searchHint")}
          name="q"
          type="search"
          maxLength={512}
          value={text.q}
          onChange={(e) => setText({ ...text, q: e.target.value })}
          autoComplete="off"
          spellCheck={false}
        />
        <Field
          label={t("findings.filters.category")}
          hint={t("findings.filters.categoryHint")}
          name="category"
          value={text.category}
          onChange={(e) => setText({ ...text, category: e.target.value })}
          autoComplete="off"
        />
        <Field
          label={t("findings.filters.run")}
          hint={t("findings.filters.runHint")}
          name="run"
          mono
          value={text.run}
          onChange={(e) => setText({ ...text, run: e.target.value })}
          autoComplete="off"
          spellCheck={false}
        />
        <Button type="submit" variant="primary">
          <Search aria-hidden="true" className="size-4" />
          {t("findings.filters.apply")}
        </Button>
      </form>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <div className="flex min-w-0 flex-col gap-2">
          <CheckGroup
            legend={t("findingState.label")}
            hint={t("findings.filters.stateHint")}
            values={findingStateList}
            selected={filters.states}
            label={(s) => t(`findingState.${s}`)}
            onToggle={(s) => onChange({ ...filters, states: toggleValue(filters.states, s, findingStateList) })}
          />
          <div>
            <Button
              variant="ghost"
              onClick={() => onChange({ ...filters, states: onlyOpen ? [] : [...openStates] })}
            >
              {onlyOpen ? t("findings.filters.allStates") : t("findings.filters.onlyOpen")}
            </Button>
          </div>
        </div>
        <div className="flex min-w-0 flex-col gap-4">
          <CheckGroup
            legend={t("severity.label")}
            values={severityList}
            selected={filters.severities}
            label={(s) => t(`severity.${s}`)}
            onToggle={(s) => onChange({ ...filters, severities: toggleValue(filters.severities, s, severityList) })}
          />
          <CheckGroup
            legend={t("findings.kind.label")}
            values={kindList}
            selected={filters.kinds}
            label={(k) => t(`findings.kind.${k}`)}
            onToggle={(k) => onChange({ ...filters, kinds: toggleValue(filters.kinds, k, kindList) })}
          />
        </div>
      </div>
    </section>
  );
}
