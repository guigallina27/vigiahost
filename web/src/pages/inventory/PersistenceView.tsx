import { CircleMinus, CirclePlus, Info, PencilLine } from "lucide-react";
import { useId, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Badge } from "../../components/Badge";
import { HashText } from "../../components/HashText";
import { PathText } from "../../components/PathText";
import { formatNumber } from "../../lib/format";
import {
  groupPersistence,
  isKnownKind,
  packageState,
  summarizeChanges,
  type PersistenceEntry,
  type PersistenceInventory,
} from "./processes";
import { SafeText } from "./SafeText";
import { TableScroll } from "../../components/TableScroll";

/** Nome do tipo de persistência em linguagem do operador (tipo desconhecido aparece como veio). */
export function KindLabel({ kind }: { kind: string }) {
  const { t } = useTranslation();
  return isKnownKind(kind) ? <>{t(`inventory.kinds.${kind}`)}</> : <SafeText text={kind} mono />;
}

function ChangeBadge({ change }: { change: PersistenceEntry["change"] }) {
  const { t } = useTranslation();
  if (change === "added")
    return (
      <Badge tone="high" icon={CirclePlus} variant="outline">
        {t("inventory.persistence.added")}
      </Badge>
    );
  if (change === "changed")
    return (
      <Badge tone="medium" icon={PencilLine} variant="outline">
        {t("inventory.persistence.changed")}
      </Badge>
    );
  if (change === "removed")
    return (
      <Badge tone="neutral" icon={CircleMinus} variant="outline">
        {t("inventory.persistence.removed")}
      </Badge>
    );
  return <span className="text-sm text-ink-muted">{t("inventory.persistence.unchanged")}</span>;
}

/** Inventário de persistência agrupado por tipo, com o que mudou desde a inspeção anterior. */
export function PersistenceView({ inventory }: { inventory: PersistenceInventory }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const [onlyChanged, setOnlyChanged] = useState(false);
  const changedId = useId();
  const summary = summarizeChanges(inventory);
  const groups = useMemo(() => groupPersistence(inventory.items, onlyChanged), [inventory.items, onlyChanged]);
  const removed = inventory.removed ?? [];
  const showChanges = !inventory.baseline;

  return (
    <div className="flex min-w-0 flex-col gap-6">
      {inventory.baseline && (
        <p className="m-0 flex items-start gap-2 rounded-control border border-line-strong bg-accent-soft p-3">
          <Info aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-accent" />
          <span>{t("inventory.persistence.baseline")}</span>
        </p>
      )}

      <dl className="m-0 grid grid-cols-2 gap-4 rounded-panel border border-line bg-surface p-4 sm:grid-cols-4">
        <SummaryItem label={t("inventory.persistence.summaryTotal")} value={formatNumber(summary.total, lng)} />
        <SummaryItem
          label={t("inventory.persistence.summaryAdded")}
          value={showChanges ? formatNumber(summary.added, lng) : "—"}
        />
        <SummaryItem
          label={t("inventory.persistence.summaryChanged")}
          value={showChanges ? formatNumber(summary.changed, lng) : "—"}
        />
        <SummaryItem
          label={t("inventory.persistence.summaryRemoved")}
          value={showChanges ? formatNumber(summary.removed, lng) : "—"}
        />
      </dl>

      {showChanges && (
        <label htmlFor={changedId} className="inline-flex min-h-11 w-fit cursor-pointer items-center gap-2 font-semibold">
          <input
            id={changedId}
            type="checkbox"
            className="size-5 accent-(--vh-accent)"
            checked={onlyChanged}
            onChange={(e) => setOnlyChanged(e.target.checked)}
          />
          {t("inventory.persistence.onlyChanged")}
        </label>
      )}

      {groups.length === 0 ? (
        <p role="status" className="m-0 rounded-panel border border-dashed border-line-strong bg-surface p-6 text-ink-muted">
          {onlyChanged ? t("inventory.persistence.noChanges") : t("inventory.persistence.empty")}
        </p>
      ) : (
        groups.map((g) => <PersistenceGroupTable key={g.kind} kind={g.kind} items={g.items} showChanges={showChanges} />)
      )}

      {showChanges && removed.length > 0 && (
        <section className="flex min-w-0 flex-col gap-3" aria-labelledby={`${changedId}-removidos`}>
          <h2 id={`${changedId}-removidos`} className="m-0 text-lg font-bold">
            {t("inventory.persistence.removedTitle", { count: removed.length })}
          </h2>
          <p className="m-0 text-sm text-ink-muted">{t("inventory.persistence.removedHint")}</p>
          <ul className="m-0 flex list-none flex-col gap-2 p-0">
            {removed.map((r) => (
              <li
                key={`${r.kind}|${r.path}`}
                className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-1 rounded-control border border-line bg-surface p-3"
              >
                <ChangeBadge change="removed" />
                <span className="text-sm text-ink-muted">
                  <KindLabel kind={r.kind} />
                </span>
                <span className="min-w-0 basis-full">
                  <PathText path={r.path} />
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

function SummaryItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid min-w-0 gap-0.5">
      <dt className="text-sm text-ink-muted">{label}</dt>
      <dd className="m-0 text-2xl font-bold tabular-nums">{value}</dd>
    </div>
  );
}

function PersistenceGroupTable({ kind, items, showChanges }: { kind: string; items: PersistenceEntry[]; showChanges: boolean }) {
  const { t } = useTranslation();
  const headingId = useId();
  return (
    <section className="flex min-w-0 flex-col gap-2" aria-labelledby={headingId}>
      <h2 id={headingId} className="m-0 flex flex-wrap items-baseline gap-x-2 text-lg font-bold">
        <KindLabel kind={kind} />
        <span className="text-sm font-normal text-ink-muted">{t("inventory.persistence.itemCount", { count: items.length })}</span>
      </h2>
      <TableScroll label={isKnownKind(kind) ? t(`inventory.kinds.${kind}`) : kind}>
        <table className="vh-table">
          <caption className="visually-hidden">
            <KindLabel kind={kind} />
          </caption>
          <thead>
            <tr>
              <th scope="col">{t("inventory.persistence.colPath")}</th>
              <th scope="col">{t("inventory.persistence.colOwner")}</th>
              <th scope="col">{t("inventory.persistence.colPackage")}</th>
              <th scope="col">{t("inventory.persistence.colHash")}</th>
              <th scope="col">{t("inventory.persistence.colDetail")}</th>
              {showChanges && <th scope="col">{t("inventory.persistence.colChange")}</th>}
            </tr>
          </thead>
          <tbody>
            {items.map((it) => {
              const pkg = packageState(it.package);
              return (
                <tr key={it.path}>
                  <td className="min-w-64">
                    <PathText path={it.path} />
                  </td>
                  <td className="min-w-24">{it.owner ? <SafeText text={it.owner} /> : <span className="text-ink-muted">—</span>}</td>
                  <td className="min-w-28">
                    {pkg === "known" ? (
                      <SafeText text={it.package ?? ""} mono />
                    ) : pkg === "none" ? (
                      <>
                        <span aria-hidden="true">—</span>
                        <span className="visually-hidden">{t("inventory.noPackage")}</span>
                      </>
                    ) : (
                      <span className="text-sm text-ink-muted">{t("inventory.packageUnknown")}</span>
                    )}
                  </td>
                  <td className="whitespace-nowrap">
                    {it.sha256 ? <HashText value={it.sha256} /> : <span className="text-ink-muted">—</span>}
                  </td>
                  <td className="min-w-40">
                    {it.detail ? <SafeText text={it.detail} /> : <span className="text-ink-muted">—</span>}
                  </td>
                  {showChanges && (
                    <td className="whitespace-nowrap">
                      <ChangeBadge change={it.change} />
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableScroll>
    </section>
  );
}
