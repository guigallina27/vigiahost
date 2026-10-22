import { useQuery } from "@tanstack/react-query";
import { FilterX, Info, PlugZap, RefreshCw, ScanSearch, SearchX, ServerCrash, Users, X } from "lucide-react";
import { useDeferredValue, useEffect, useId, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";
import { useCurrentUser } from "../../auth/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { Field, SelectField } from "../../components/Field";
import { PathText } from "../../components/PathText";
import { SeverityCounts } from "../../components/SeverityCounts";
import { TableScroll } from "../../components/TableScroll";
import { Timestamp } from "../../components/Timestamp";
import { PageHeader } from "../../layout/PageHeader";
import { formatNumber } from "../../lib/format";
import { SafeText } from "../inventory/SafeText";
import { newIdempotencyKey, toDate } from "../runs/runFormat";
import {
  accountFiltersToParams,
  accountFindingsHref,
  accountHref,
  ACCOUNT_SORTS,
  isExecutorUnavailable,
  narrowsList,
  parseAccountFilters,
  toggleUid,
  visibleAccounts,
  type Account,
  type AccountFilters,
  type AccountList,
  type ScanTarget,
} from "./accounts";
import { HomeWarning, LastRunCell, ScanAccountsDialog, type ScanRequest } from "./AccountParts";
import { accountsQuery } from "./queries";

/** Linhas desenhadas por vez: 5.000 contas filtram e ordenam no cliente, mas só as primeiras vão para a tabela. */
const PAGE = 100;

/**
 * Busca com o texto local (resposta imediata) e gravada no endereço depois de uma pausa na digitação. Voltar no
 * navegador ou limpar os filtros trazem o texto do endereço de volta ao campo.
 */
function useSearchText(fromUrl: string, write: (q: string) => void) {
  const [text, setText] = useState(fromUrl);
  // Último valor do endereço já refletido no campo (o que veio de fora ou o que este campo gravou).
  const [known, setKnown] = useState(fromUrl);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  // A gravação roda depois da pausa: usa sempre a função da renderização mais recente (o setSearchParams de uma
  // renderização antiga parte do endereço daquela época e desfaria filtros marcados nesse meio-tempo).
  const writeRef = useRef(write);
  useEffect(() => {
    writeRef.current = write;
  });
  if (fromUrl !== known) {
    setKnown(fromUrl);
    setText(fromUrl);
  }
  useEffect(() => {
    const pending = timer;
    return () => clearTimeout(pending.current);
  }, []);
  return {
    text,
    change(value: string) {
      setText(value);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        const q = value.trim().slice(0, 256);
        setKnown(q);
        writeRef.current(q);
      }, 250);
    },
    cancel() {
      clearTimeout(timer.current);
    },
  };
}

/** Contas do servidor (rota /contas): risco por conta, última verificação e verificação de uma, várias ou todas. */
export function AccountsPage() {
  const { t } = useTranslation();
  const { canOperate } = useCurrentUser();
  const [params, setParams] = useSearchParams();
  const filters = parseAccountFilters(params);
  const query = useQuery(accountsQuery(filters.system));
  const [scan, setScan] = useState<ScanRequest | null>(null);

  // Atualização funcional: a busca grava depois de uma pausa e não pode desfazer um filtro marcado nesse meio-tempo.
  function update(patch: Partial<AccountFilters>) {
    setParams((prev) => accountFiltersToParams({ ...parseAccountFilters(prev), ...patch }), { replace: true });
  }
  const search = useSearchText(filters.q, (q) => update({ q }));

  const scanAll = () =>
    setScan({ target: { kind: "all" }, accounts: [], key: newIdempotencyKey(), ...(query.data ? { total: query.data.accounts.length } : {}) });

  const actions = canOperate && (
    <Button variant="primary" onClick={scanAll}>
      <ScanSearch aria-hidden="true" className="size-4" />
      {t("accounts.scanAll")}
    </Button>
  );

  return (
    <>
      <PageHeader title={t("accounts.title")} subtitle={t("accounts.subtitle")} actions={actions} />
      <div className="flex min-w-0 flex-col gap-5">
        <FiltersBar
          filters={filters}
          text={search.text}
          onText={search.change}
          onChange={(patch) => update(patch)}
        />

        {query.isPending ? (
          <p className="m-0 text-ink-muted" role="status">
            {t("states.loading")}
          </p>
        ) : query.isError ? (
          <LoadError error={query.error} retry={() => void query.refetch()} busy={query.isFetching} />
        ) : (
          <AccountsList
            data={query.data}
            filters={filters}
            text={search.text}
            canOperate={canOperate}
            onIncludeSystem={() => update({ system: true })}
            onClear={() => {
              search.cancel();
              update({ q: "", withFindings: false });
            }}
            onScan={setScan}
          />
        )}
      </div>
      <ScanAccountsDialog request={scan} onClose={() => setScan(null)} />
    </>
  );
}

export default AccountsPage;

function FiltersBar({
  filters,
  text,
  onText,
  onChange,
}: {
  filters: AccountFilters;
  text: string;
  onText: (v: string) => void;
  onChange: (patch: Partial<AccountFilters>) => void;
}) {
  const { t } = useTranslation();
  const systemId = useId();
  const findingsId = useId();
  return (
    <form
      role="search"
      aria-label={t("accounts.filters.legend")}
      onSubmit={(e) => e.preventDefault()}
      className="flex min-w-0 flex-wrap items-end gap-x-6 gap-y-3"
    >
      <Field
        className="w-full max-w-md"
        type="search"
        name="q"
        label={t("accounts.filters.search")}
        hint={t("accounts.filters.searchHint")}
        value={text}
        maxLength={256}
        onChange={(e) => onText(e.target.value)}
        autoComplete="off"
        spellCheck={false}
      />
      <SelectField
        className="w-full sm:w-64"
        name="sort"
        label={t("accounts.filters.sort")}
        value={filters.sort}
        onChange={(e) => onChange({ sort: ACCOUNT_SORTS.find((s) => s === e.target.value) ?? "risk" })}
        options={ACCOUNT_SORTS.map((s) => ({ value: s, label: t(`accounts.sort.${s}`) }))}
      />
      <div className="flex flex-wrap gap-x-6 gap-y-2">
        <label htmlFor={findingsId} className="inline-flex min-h-11 cursor-pointer items-center gap-2 font-semibold">
          <input
            id={findingsId}
            type="checkbox"
            className="size-5 accent-(--vh-accent)"
            checked={filters.withFindings}
            onChange={(e) => onChange({ withFindings: e.target.checked })}
          />
          {t("accounts.filters.withFindings")}
        </label>
        <label htmlFor={systemId} className="inline-flex min-h-11 cursor-pointer items-center gap-2 font-semibold">
          <input
            id={systemId}
            type="checkbox"
            className="size-5 accent-(--vh-accent)"
            checked={filters.system}
            onChange={(e) => onChange({ system: e.target.checked })}
          />
          {t("accounts.filters.system")}
        </label>
      </div>
    </form>
  );
}

function LoadError({ error, retry, busy }: { error: Error; retry: () => void; busy: boolean }) {
  const { t } = useTranslation();
  const action = (
    <Button onClick={retry} disabled={busy}>
      <RefreshCw aria-hidden="true" className="size-4" />
      {t("states.retry")}
    </Button>
  );
  if (isExecutorUnavailable(error)) {
    return (
      <EmptyState
        tone="error"
        icon={ServerCrash}
        title={t("accounts.errors.executorTitle")}
        description={
          <div role="alert" className="flex flex-col gap-2">
            <p className="m-0">{t("accounts.errors.executorDescription")}</p>
            <p className="m-0">
              {t("accounts.errors.executorAction")} <code className="font-mono">systemctl status vigiahost-executor</code>
            </p>
          </div>
        }
        action={action}
      />
    );
  }
  return (
    <EmptyState
      tone="error"
      icon={PlugZap}
      title={t("accounts.errors.loadTitle")}
      description={<p className="m-0" role="alert">{error.message}</p>}
      action={action}
    />
  );
}

function AccountsList({
  data,
  filters,
  text,
  canOperate,
  onIncludeSystem,
  onClear,
  onScan,
}: {
  data: AccountList;
  filters: AccountFilters;
  text: string;
  canOperate: boolean;
  onIncludeSystem: () => void;
  onClear: () => void;
  onScan: (r: ScanRequest) => void;
}) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const q = useDeferredValue(text);
  const { withFindings, sort, system } = filters;
  const rows = useMemo(
    () => visibleAccounts(data.accounts, { q, withFindings, sort, system }),
    [data.accounts, q, withFindings, sort, system],
  );
  const [selected, setSelected] = useState<number[]>([]);

  // "Mostrar mais" volta ao começo quando a lista muda de filtro ou de ordem.
  const listKey = `${q}|${withFindings}|${sort}|${system}`;
  const [limit, setLimit] = useState({ key: listKey, n: PAGE });
  const shown = limit.key === listKey ? limit.n : PAGE;
  const page = rows.slice(0, shown);

  if (data.accounts.length === 0) {
    return system ? (
      <EmptyState icon={Users} title={t("accounts.empty.noneTitle")} description={t("accounts.empty.noneDescription")} />
    ) : (
      <EmptyState
        icon={Users}
        title={t("accounts.empty.title")}
        description={t("accounts.empty.description", { min: data.uid_min, max: data.uid_max })}
        action={
          <Button onClick={onIncludeSystem}>
            <Users aria-hidden="true" className="size-4" />
            {t("accounts.empty.includeSystem")}
          </Button>
        }
      />
    );
  }

  const byUid = new Map(data.accounts.map((a) => [a.uid, a]));
  const scanTarget = (target: ScanTarget, accounts: Account[]) => onScan({ target, accounts, key: newIdempotencyKey() });

  return (
    <div className="flex min-w-0 flex-col gap-3">
      <div className="flex flex-col gap-1 text-sm text-ink-muted">
        <p className="m-0" role="status">
          {t("accounts.showing", {
            count: data.accounts.length,
            shown: formatNumber(rows.length, lng),
            total: formatNumber(data.accounts.length, lng),
          })}
        </p>
        <p className="m-0">{t("accounts.uidRange", { min: data.uid_min, max: data.uid_max })}</p>
        <InventoryNote at={data.inventory_at} />
      </div>

      {canOperate && selected.length > 0 && (
        <div className="flex flex-wrap items-center gap-3 rounded-control border border-line-strong bg-accent-soft p-3">
          <p className="m-0 font-semibold">{t("accounts.selection.count", { count: selected.length, formatted: formatNumber(selected.length, lng) })}</p>
          <Button
            variant="primary"
            onClick={() =>
              scanTarget(
                { kind: "uids", uids: selected },
                selected.map((uid) => byUid.get(uid) ?? fallbackAccount(uid)),
              )
            }
          >
            <ScanSearch aria-hidden="true" className="size-4" />
            {t("accounts.selection.scan")}
          </Button>
          <Button variant="ghost" onClick={() => setSelected([])}>
            <X aria-hidden="true" className="size-4" />
            {t("accounts.selection.clear")}
          </Button>
        </div>
      )}

      {rows.length === 0 ? (
        <EmptyState
          icon={SearchX}
          title={t("accounts.empty.filteredTitle")}
          description={t("accounts.empty.filteredDescription")}
          action={
            narrowsList({ ...filters, q }) && (
              <Button onClick={onClear}>
                <FilterX aria-hidden="true" className="size-4" />
                {t("accounts.filters.clear")}
              </Button>
            )
          }
        />
      ) : (
        <>
          <AccountsTable
            accounts={page}
            canOperate={canOperate}
            selected={selected}
            onToggle={(uid) => setSelected((s) => toggleUid(s, uid))}
            onToggleAll={(on) =>
              setSelected((s) => {
                const uids = page.map((a) => a.uid);
                return on ? [...new Set([...s, ...uids])].sort((a, b) => a - b) : s.filter((u) => !uids.includes(u));
              })
            }
            onScanOne={(a) => scanTarget({ kind: "uids", uids: [a.uid] }, [a])}
          />
          {rows.length > shown && (
            <div className="flex flex-wrap items-center gap-3">
              <Button onClick={() => setLimit({ key: listKey, n: shown + PAGE })}>
                {t("accounts.showMore", { count: Math.min(PAGE, rows.length - shown) })}
              </Button>
              <span className="text-sm text-ink-muted">
                {t("accounts.shownOf", { shown: formatNumber(shown, lng), total: formatNumber(rows.length, lng) })}
              </span>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function fallbackAccount(uid: number): Account {
  return {
    uid,
    name: String(uid),
    home: "",
    shell: "",
    system: false,
    home_ok: false,
    open_findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    processes: -1,
    persistence_items: -1,
  };
}

function InventoryNote({ at }: { at: string | undefined }) {
  const { t } = useTranslation();
  const date = toDate(at);
  if (!date) {
    return (
      <p className="m-0 flex items-start gap-1.5">
        <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
        <span>
          {t("accounts.noInventory")}{" "}
          <Link to="/processos" className="font-semibold">
            {t("accounts.openInventory")}
          </Link>
        </span>
      </p>
    );
  }
  return (
    <p className="m-0">
      {t("accounts.inventoryAt")} <Timestamp date={date} compact />
    </p>
  );
}

function AccountsTable({
  accounts,
  canOperate,
  selected,
  onToggle,
  onToggleAll,
  onScanOne,
}: {
  accounts: Account[];
  canOperate: boolean;
  selected: number[];
  onToggle: (uid: number) => void;
  onToggleAll: (on: boolean) => void;
  onScanOne: (a: Account) => void;
}) {
  const { t } = useTranslation();
  const chosen = new Set(selected);
  const allOn = accounts.length > 0 && accounts.every((a) => chosen.has(a.uid));
  const someOn = !allOn && accounts.some((a) => chosen.has(a.uid));
  return (
    <TableScroll label={t("accounts.table.caption")}>
      <table className="vh-table">
        <caption className="visually-hidden">{t("accounts.table.caption")}</caption>
        <thead>
          <tr>
            {canOperate && (
              <th scope="col" className="w-12">
                <label className="inline-flex min-h-11 min-w-11 cursor-pointer items-center justify-center">
                  <input
                    type="checkbox"
                    className="size-5 accent-(--vh-accent)"
                    checked={allOn}
                    ref={(el) => {
                      if (el) el.indeterminate = someOn;
                    }}
                    onChange={(e) => onToggleAll(e.target.checked)}
                  />
                  <span className="visually-hidden">{t("accounts.table.selectShown")}</span>
                </label>
              </th>
            )}
            <th scope="col">{t("accounts.table.account")}</th>
            <th scope="col">{t("accounts.table.home")}</th>
            <th scope="col">{t("accounts.table.findings")}</th>
            <th scope="col">{t("accounts.table.lastRun")}</th>
            <th scope="col" className="text-end">
              {t("accounts.table.processes")}
            </th>
            <th scope="col" className="text-end">
              {t("accounts.table.persistence")}
            </th>
            {canOperate && <th scope="col">{t("accounts.table.actions")}</th>}
          </tr>
        </thead>
        <tbody>
          {accounts.map((a) => (
            <AccountRow
              key={a.uid}
              account={a}
              canOperate={canOperate}
              checked={chosen.has(a.uid)}
              onToggle={() => onToggle(a.uid)}
              onScan={() => onScanOne(a)}
            />
          ))}
        </tbody>
      </table>
    </TableScroll>
  );
}

function AccountRow({
  account: a,
  canOperate,
  checked,
  onToggle,
  onScan,
}: {
  account: Account;
  canOperate: boolean;
  checked: boolean;
  onToggle: () => void;
  onScan: () => void;
}) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  return (
    <tr>
      {canOperate && (
        <td>
          <label className="inline-flex min-h-11 min-w-11 cursor-pointer items-center justify-center">
            <input type="checkbox" className="size-5 accent-(--vh-accent)" checked={checked} onChange={onToggle} />
            <span className="visually-hidden">{t("accounts.table.select", { name: a.name })}</span>
          </label>
        </td>
      )}
      <td className="min-w-40">
        <Link to={accountHref(a.uid)} className="font-semibold">
          <SafeText text={a.name} />
        </Link>
        <span className="mt-0.5 flex flex-wrap items-center gap-2 text-sm text-ink-muted">
          <span className="tabular-nums">{t("accounts.uid", { uid: a.uid })}</span>
          {a.system && (
            <Badge tone="neutral" icon={Users} variant="outline">
              {t("accounts.kind.system")}
            </Badge>
          )}
        </span>
      </td>
      <td className="min-w-48">
        <PathText path={a.home} />
        {!a.home_ok && <HomeWarning />}
      </td>
      <td className="min-w-48">
        <SeverityCounts counts={a.open_findings} />
        {a.open_findings.total > 0 && (
          <Link to={accountFindingsHref(a.uid)} className="mt-1 inline-block text-sm font-semibold">
            {t("accounts.table.viewFindings", { count: a.open_findings.total, formatted: formatNumber(a.open_findings.total, lng) })}
            <span className="visually-hidden"> {t("accounts.table.ofAccount", { name: a.name })}</span>
          </Link>
        )}
      </td>
      <td className="min-w-48">
        <LastRunCell account={a} />
      </td>
      <td className="text-end tabular-nums">
        <InventoryCount value={a.processes} />
      </td>
      <td className="text-end tabular-nums">
        <InventoryCount value={a.persistence_items} />
      </td>
      {canOperate && (
        <td>
          {/* Nome com a conta (o rótulo visível vem primeiro, WCAG 2.5.3): cada linha tem o seu botão. */}
          <Button onClick={onScan} className="whitespace-nowrap" aria-label={t("accounts.table.scanNamed", { name: a.name })}>
            <ScanSearch aria-hidden="true" className="size-4" />
            {t("accounts.scanOne")}
          </Button>
        </td>
      )}
    </tr>
  );
}

/** Contagem do inventário; -1 quer dizer que nenhuma inspeção de processos rodou ainda. */
function InventoryCount({ value }: { value: number }) {
  const { t, i18n } = useTranslation();
  if (value < 0) return <span className="text-sm text-ink-muted">{t("accounts.noInspection")}</span>;
  return <>{formatNumber(value, i18n.language)}</>;
}
