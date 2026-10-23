import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArchiveRestore,
  CalendarClock,
  CircleArrowUp,
  DatabaseBackup,
  MousePointerClick,
  PlugZap,
  RefreshCw,
  Terminal,
  type LucideIcon,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { api, unwrap, type Schemas } from "../../api/client";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { HashText } from "../../components/HashText";
import { Panel } from "../../components/Panel";
import { PathText } from "../../components/PathText";
import { Timestamp } from "../../components/Timestamp";
import { PageHeader } from "../../layout/PageHeader";
import { formatBytes } from "../config/units";
import { SafeText } from "./SecretOnce";
import { useSensitiveAction } from "./SensitiveDialog";
import { TableScroll } from "../../components/TableScroll";

export const backupsQueryKey = ["backups"] as const;

type BackupInfo = Schemas["BackupInfo"];

// O selo nunca depende só da cor: cada origem tem um ícone próprio.
const originIcon: Record<BackupInfo["origin"], LucideIcon> = {
  automatic: CalendarClock,
  manual: MousePointerClick,
  cli: Terminal,
  "pre-migration": CircleArrowUp,
  "pre-restore": ArchiveRestore,
};

/**
 * Cópias do banco do core (E1.14). A interface só cria e lista: restaurar exige parar o serviço, e isso fica com
 * o root no terminal ("vigiahost backup restore"), nunca com o painel.
 */
export function BackupPage() {
  const { t, i18n } = useTranslation();
  const qc = useQueryClient();
  const backups = useQuery({
    queryKey: backupsQueryKey,
    queryFn: ({ signal }) => unwrap(api.GET("/api/v1/backups", { signal })),
  });
  const sensitive = useSensitiveAction();
  const list = backups.data?.backups ?? [];

  function askCreate() {
    sensitive.ask({
      title: t("admin.backup.confirmTitle"),
      object: <span>{t("admin.backup.confirmObject")}</span>,
      impact: t("admin.backup.confirmImpact"),
      reversible: true,
      destructive: false,
      confirmLabel: t("admin.backup.create"),
      run: async () => {
        await unwrap(api.POST("/api/v1/backups"));
        await qc.invalidateQueries({ queryKey: backupsQueryKey });
      },
    });
  }

  return (
    <>
      <PageHeader
        title={t("admin.backup.title")}
        subtitle={t("admin.backup.subtitle")}
        actions={
          <Button variant="primary" onClick={askCreate} disabled={!backups.data}>
            <DatabaseBackup aria-hidden="true" className="size-4" />
            {t("admin.backup.create")}
          </Button>
        }
      />
      <div className="flex flex-col gap-6">
        <Panel
          title={t("admin.backup.listTitle")}
          actions={backups.data && <span className="text-sm text-ink-muted">{t("admin.backup.count", { count: list.length })}</span>}
        >
          {backups.data && (
            <p className="m-0 text-sm text-ink-muted">
              {t("admin.backup.retention", { count: backups.data.keep_automatic })}
            </p>
          )}
          {backups.isPending ? (
            <p className="m-0 text-ink-muted">{t("states.loading")}</p>
          ) : backups.isError ? (
            <EmptyState
              tone="error"
              icon={PlugZap}
              headingLevel={3}
              title={t("admin.common.loadErrorTitle")}
              description={backups.error.message}
              action={
                <Button onClick={() => void backups.refetch()} disabled={backups.isFetching}>
                  <RefreshCw aria-hidden="true" className="size-4" />
                  {t("states.retry")}
                </Button>
              }
            />
          ) : list.length === 0 ? (
            <EmptyState icon={DatabaseBackup} headingLevel={3} title={t("admin.backup.emptyTitle")} description={t("admin.backup.empty")} />
          ) : (
            <BackupTable backups={list} locale={i18n.language} />
          )}
        </Panel>

        <Panel title={t("admin.backup.restoreTitle")}>
          <div className="grid gap-3">
            <p className="m-0">{t("admin.backup.restoreIntro")}</p>
            <ol className="m-0 grid gap-2 ps-5">
              <li>
                {t("admin.backup.restoreStop")} <code className="font-mono">systemctl stop vigiahost-core</code>
              </li>
              <li>
                {t("admin.backup.restoreRun")} <code className="font-mono break-all">sudo vigiahost backup restore {list[0]?.name ?? "vigiahost-AAAAMMDD-HHMMSS.db"}</code>
              </li>
              <li>
                {t("admin.backup.restoreStart")} <code className="font-mono">systemctl start vigiahost-core</code>
              </li>
            </ol>
            <p className="m-0 flex items-start gap-2 text-sm text-ink-muted">
              <Terminal aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
              <span>{t("admin.backup.restoreSafety")}</span>
            </p>
            {backups.data && (
              <p className="m-0 text-sm text-ink-muted">
                {t("admin.backup.directory")} <PathText path={backups.data.directory} />
              </p>
            )}
          </div>
        </Panel>
      </div>
      {sensitive.dialog}
    </>
  );
}

function BackupTable({ backups, locale }: { backups: readonly BackupInfo[]; locale: string }) {
  const { t } = useTranslation();
  return (
    <TableScroll label={t("admin.backup.listTitle")}>
      <table className="vh-table">
        <caption className="visually-hidden">{t("admin.backup.listTitle")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("admin.backup.colName")}</th>
            <th scope="col">{t("admin.backup.colCreated")}</th>
            <th scope="col">{t("admin.backup.colOrigin")}</th>
            <th scope="col">{t("admin.backup.colSize")}</th>
            <th scope="col">{t("admin.backup.colSchema")}</th>
            <th scope="col">{t("admin.backup.colHash")}</th>
          </tr>
        </thead>
        <tbody>
          {backups.map((b) => (
            <tr key={b.name}>
              <th scope="row" className="text-left font-normal">
                <SafeText value={b.name} mono />
              </th>
              <td>
                <Timestamp date={new Date(b.created_at)} compact />
              </td>
              <td>
                <Badge tone={b.origin === "automatic" ? "neutral" : "low"} variant="outline" icon={originIcon[b.origin]}>
                  {t(`admin.backup.origin.${b.origin}`)}
                </Badge>
              </td>
              <td className="tabular-nums">{formatBytes(b.size, locale)}</td>
              <td className="tabular-nums">
                {b.schema_version}
                <span className="block text-sm text-ink-muted">
                  <SafeText value={b.product} mono />
                </span>
              </td>
              <td>
                <HashText value={b.sha256} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableScroll>
  );
}

export default BackupPage;
