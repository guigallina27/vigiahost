import { ArrowDown, ArrowUp, ArrowUpDown, FileX, Flag, MemoryStick } from "lucide-react";
import { useId, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { Badge } from "../../components/Badge";
import { Field } from "../../components/Field";
import { HashText } from "../../components/HashText";
import { PathText } from "../../components/PathText";
import { formatNumber } from "../../lib/format";
import { formatBytes } from "../config/units";
import {
  emptyFilter,
  filterProcesses,
  findingsLink,
  formatCpu,
  packageState,
  sortProcesses,
  type ProcessFilter,
  type ProcessInfo,
  type ProcessSortKey,
  type SortDirection,
} from "./processes";
import { SafeText } from "./SafeText";
import { TableScroll } from "../../components/TableScroll";

/** Tabela filtrável e ordenável dos processos de um instantâneo. */
export function ProcessTable({ processes }: { processes: ProcessInfo[] }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const [filter, setFilter] = useState<ProcessFilter>(emptyFilter);
  const [sort, setSort] = useState<{ key: ProcessSortKey; dir: SortDirection }>({ key: "cpu", dir: "desc" });
  const flaggedId = useId();
  const networkId = useId();

  const rows = useMemo(
    () => sortProcesses(filterProcesses(processes, filter), sort.key, sort.dir),
    [processes, filter, sort],
  );

  function toggleSort(key: ProcessSortKey) {
    setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: key === "pid" ? "asc" : "desc" }));
  }

  const flaggedTotal = processes.filter((p) => (p.flags?.length ?? 0) > 0).length;

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <div className="flex flex-wrap items-end gap-x-6 gap-y-3" role="search">
        <Field
          className="w-full max-w-md"
          type="search"
          label={t("inventory.processes.search")}
          hint={t("inventory.processes.searchHint")}
          value={filter.query}
          onChange={(e) => setFilter((f) => ({ ...f, query: e.target.value }))}
          autoComplete="off"
          spellCheck={false}
        />
        <div className="flex flex-wrap gap-x-6 gap-y-2">
          <label htmlFor={flaggedId} className="inline-flex min-h-11 cursor-pointer items-center gap-2 font-semibold">
            <input
              id={flaggedId}
              type="checkbox"
              className="size-5 accent-(--vh-accent)"
              checked={filter.onlyFlagged}
              onChange={(e) => setFilter((f) => ({ ...f, onlyFlagged: e.target.checked }))}
            />
            {t("inventory.processes.onlyFlagged", { count: flaggedTotal })}
          </label>
          <label htmlFor={networkId} className="inline-flex min-h-11 cursor-pointer items-center gap-2 font-semibold">
            <input
              id={networkId}
              type="checkbox"
              className="size-5 accent-(--vh-accent)"
              checked={filter.onlyNetwork}
              onChange={(e) => setFilter((f) => ({ ...f, onlyNetwork: e.target.checked }))}
            />
            {t("inventory.processes.onlyNetwork")}
          </label>
        </div>
      </div>

      <p role="status" className="m-0 text-sm text-ink-muted">
        {t("inventory.processes.showing", {
          count: processes.length,
          shown: formatNumber(rows.length, lng),
          total: formatNumber(processes.length, lng),
        })}
      </p>

      {rows.length === 0 ? (
        <p className="m-0 rounded-panel border border-dashed border-line-strong bg-surface p-6 text-ink-muted">
          {t("inventory.processes.noMatch")}
        </p>
      ) : (
        <TableScroll label={t("inventory.processes.caption")}>
          <table className="vh-table">
            <caption className="visually-hidden">{t("inventory.processes.caption")}</caption>
            <thead>
              <tr>
                <SortHeader label={t("inventory.processes.colPid")} sortKey="pid" sort={sort} onSort={toggleSort} />
                <th scope="col">{t("inventory.processes.colUser")}</th>
                <th scope="col">{t("inventory.processes.colProcess")}</th>
                <th scope="col">{t("inventory.processes.colPackage")}</th>
                <th scope="col">{t("inventory.processes.colUnit")}</th>
                <SortHeader label={t("inventory.processes.colCpu")} sortKey="cpu" sort={sort} onSort={toggleSort} />
                <SortHeader label={t("inventory.processes.colMemory")} sortKey="memory" sort={sort} onSort={toggleSort} />
                <th scope="col">{t("inventory.processes.colSockets")}</th>
                <th scope="col">{t("inventory.processes.colFlags")}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((p) => (
                <ProcessRow key={`${p.pid}-${p.start_ticks ?? 0}`} p={p} />
              ))}
            </tbody>
          </table>
        </TableScroll>
      )}
      <p className="m-0 text-sm text-ink-muted">{t("inventory.processes.legend")}</p>
    </div>
  );
}

function SortHeader({
  label,
  sortKey,
  sort,
  onSort,
}: {
  label: string;
  sortKey: ProcessSortKey;
  sort: { key: ProcessSortKey; dir: SortDirection };
  onSort: (k: ProcessSortKey) => void;
}) {
  const { t } = useTranslation();
  const active = sort.key === sortKey;
  const Icon = !active ? ArrowUpDown : sort.dir === "asc" ? ArrowUp : ArrowDown;
  return (
    <th scope="col" aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : "none"} className="p-0!">
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className="inline-flex min-h-11 w-full cursor-pointer items-center gap-1.5 px-3 text-start font-semibold whitespace-nowrap hover:text-ink"
      >
        {label}
        <Icon aria-hidden="true" className={`size-4 shrink-0 ${active ? "text-ink" : ""}`} />
        <span className="visually-hidden">
          {active
            ? t(sort.dir === "asc" ? "inventory.processes.sortedAsc" : "inventory.processes.sortedDesc")
            : t("inventory.processes.sortBy")}
        </span>
      </button>
    </th>
  );
}

function ProcessRow({ p }: { p: ProcessInfo }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const flags = p.flags ?? [];
  const listening = p.listening ?? [];
  const connected = p.connected ?? [];
  const pkg = packageState(p.package);
  const exe = p.exe.replace(/ \(deleted\)$/, "");

  return (
    <tr className={flags.length > 0 ? "bg-(--vh-high-bg)/40" : undefined}>
      <td className="tabular-nums whitespace-nowrap">
        <span className="font-semibold">{p.pid}</span>
        <span className="block text-sm text-ink-muted">{t("inventory.processes.ppid", { ppid: p.ppid })}</span>
      </td>
      <td className="min-w-24">
        {p.user ? <SafeText text={p.user} /> : <span className="text-ink-muted">{t("inventory.processes.uid", { uid: p.uid })}</span>}
      </td>
      <td className="min-w-64">
        <div className="flex min-w-0 flex-col gap-1">
          <span className="font-semibold">
            <SafeText text={p.comm} />
          </span>
          <span className="text-sm">
            {exe ? <PathText path={exe} /> : <span className="text-ink-muted">{t("inventory.processes.noExe")}</span>}
          </span>
          {(p.exe_memfd || p.exe_deleted) && (
            <span className="flex flex-wrap gap-1">
              {p.exe_memfd && (
                <Badge tone="critical" icon={MemoryStick}>
                  {t("inventory.processes.memfd")}
                </Badge>
              )}
              {p.exe_deleted && !p.exe_memfd && (
                <Badge tone="high" icon={FileX}>
                  {t("inventory.processes.deleted")}
                </Badge>
              )}
            </span>
          )}
          <details className="text-sm">
            <summary className="inline-flex min-h-11 cursor-pointer items-center font-semibold text-accent">
              {t("inventory.processes.details")}
            </summary>
            <dl className="m-0 mt-1 grid gap-2">
              <div className="grid gap-0.5">
                <dt className="text-ink-muted">{t("inventory.processes.cmdline")}</dt>
                <dd className="m-0 rounded-control bg-sunken p-2">
                  {p.cmdline && p.cmdline.length > 0 ? (
                    <PathText path={p.cmdline.join(" ")} />
                  ) : (
                    <span className="text-ink-muted">{t("inventory.processes.noCmdline")}</span>
                  )}
                </dd>
                <dd className="m-0 text-ink-muted">{t("inventory.processes.cmdlineMasked")}</dd>
              </div>
              {p.exe_sha256 && (
                <div className="grid gap-0.5">
                  <dt className="text-ink-muted">{t("inventory.processes.sha256")}</dt>
                  <dd className="m-0">
                    <HashText value={p.exe_sha256} />
                  </dd>
                </div>
              )}
              {p.cgroup && (
                <div className="grid gap-0.5">
                  <dt className="text-ink-muted">{t("inventory.processes.cgroup")}</dt>
                  <dd className="m-0">
                    <PathText path={p.cgroup} />
                  </dd>
                </div>
              )}
              <div className="grid gap-0.5">
                <dt className="text-ink-muted">{t("inventory.processes.threads")}</dt>
                <dd className="m-0 tabular-nums">{formatNumber(p.threads, lng)}</dd>
              </div>
            </dl>
          </details>
        </div>
      </td>
      <td className="min-w-28">
        {pkg === "known" ? (
          <SafeText text={p.package ?? ""} mono />
        ) : pkg === "none" ? (
          <>
            <span aria-hidden="true">—</span>
            <span className="visually-hidden">{t("inventory.noPackage")}</span>
          </>
        ) : (
          <span className="text-sm text-ink-muted">{t("inventory.packageUnknown")}</span>
        )}
      </td>
      <td className="min-w-32">
        {p.unit ? <SafeText text={p.unit} mono /> : <span className="text-ink-muted">{t("inventory.processes.noUnit")}</span>}
      </td>
      <td className="text-end tabular-nums whitespace-nowrap">{formatCpu(p.cpu_percent, lng)}</td>
      <td className="text-end tabular-nums whitespace-nowrap">{formatBytes(p.rss_bytes, lng)}</td>
      <td className="min-w-36">
        {listening.length === 0 && connected.length === 0 ? (
          <span className="text-ink-muted">{t("inventory.processes.noSockets")}</span>
        ) : (
          <div className="flex flex-col gap-0.5 text-sm">
            {listening.length > 0 && <span>{t("inventory.processes.listening", { count: listening.length })}</span>}
            {connected.length > 0 && <span>{t("inventory.processes.connected", { count: connected.length })}</span>}
            <details>
              <summary className="inline-flex min-h-11 cursor-pointer items-center font-semibold text-accent">
                {t("inventory.processes.addresses")}
              </summary>
              <ul className="m-0 flex list-none flex-col gap-1 p-0">
                {listening.map((a, i) => (
                  <li key={`l${i}`}>
                    <span className="text-ink-muted">{t("inventory.processes.listenPrefix")} </span>
                    <SafeText text={a} mono />
                  </li>
                ))}
                {connected.map((a, i) => (
                  <li key={`c${i}`}>
                    <span className="text-ink-muted">{t("inventory.processes.connectPrefix")} </span>
                    <SafeText text={a} mono />
                  </li>
                ))}
              </ul>
            </details>
          </div>
        )}
      </td>
      <td className="min-w-48">
        {flags.length === 0 ? (
          <span className="text-ink-muted">{t("inventory.processes.noFlags")}</span>
        ) : (
          <ul className="m-0 flex list-none flex-col gap-1 p-0">
            {flags.map((sig) => (
              <li key={sig}>
                <Link
                  to={findingsLink(sig)}
                  className="inline-flex min-h-11 items-center gap-1.5 font-mono text-sm font-semibold text-(--vh-high-fg) underline underline-offset-4 [overflow-wrap:anywhere]"
                >
                  <Flag aria-hidden="true" className="size-4 shrink-0" />
                  <span className="visually-hidden">{t("inventory.processes.flagLink")} </span>
                  {sig}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </td>
    </tr>
  );
}
