import { useQuery } from "@tanstack/react-query";
import { TriangleAlert } from "lucide-react";
import { Link } from "react-router";
import { useTranslation } from "react-i18next";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { FilterChip } from "../../components/FilterChip";
import { PathText } from "../../components/PathText";
import { StatusBadge } from "../../components/StatusBadge";
import { Timestamp } from "../../components/Timestamp";
import { formatNumber } from "../../lib/format";
import { SafeText } from "../inventory/SafeText";
import { toDate } from "../runs/runFormat";
import { isExecutorUnavailable, type Account, type ScanTarget } from "./accounts";
import { accountQuery, useAccountScan } from "./queries";

// Peças da área de contas usadas também por achados, execuções e agendamentos.

/** Filtro ?account= aplicado em outra lista: "Conta: loja (1001)", removível. Sem o nome, mostra só o UID. */
export function AccountFilterChip({ uid, onRemove }: { uid: number; onRemove: () => void }) {
  const { t } = useTranslation();
  const account = useQuery({ ...accountQuery(uid), staleTime: 60_000 });
  const value = account.data ? (
    <>
      <SafeText text={account.data.name} /> ({uid})
    </>
  ) : (
    t("accounts.chip.uidOnly", { uid })
  );
  return (
    <FilterChip label={t("accounts.chip.label")} value={value} onRemove={onRemove} removeLabel={t("accounts.chip.remove")} />
  );
}

/** Aviso de diretório pessoal ausente: a verificação da conta cobre só as áreas temporárias. */
export function HomeWarning() {
  const { t } = useTranslation();
  return (
    <span className="mt-1 flex items-start gap-1.5 text-sm text-(--vh-medium-fg)">
      <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
      <span>{t("accounts.homeMissing")}</span>
    </span>
  );
}

export type ScanRequest = {
  target: ScanTarget;
  /** Contas envolvidas, para mostrar no objeto da confirmação (vazio em "todas"). */
  accounts: Pick<Account, "uid" | "name" | "home">[];
  /** Quantas contas de hospedagem a lista mostra hoje (só em "todas"). */
  total?: number;
  /** Chave de idempotência gerada ao abrir o diálogo. */
  key: string | undefined;
};

const PREVIEW = 5;

/**
 * Confirmação de "verificar contas": mostra exatamente quais contas, o que entra no escopo (diretório pessoal e os
 * arquivos da conta em /tmp, /var/tmp e /dev/shm) e que dá para cancelar depois. Ao criar, abre a execução.
 */
export function ScanAccountsDialog({ request, onClose }: { request: ScanRequest | null; onClose: () => void }) {
  const { t } = useTranslation();
  const { mutation } = useAccountScan();
  const target = request?.target;
  const list = request?.accounts ?? [];
  const many = target?.kind === "uids" && target.uids.length > 1;

  const title = !target
    ? ""
    : target.kind === "all"
      ? t("accounts.scan.allTitle")
      : many
        ? t("accounts.scan.manyTitle", { count: target.uids.length })
        : t("accounts.scan.oneTitle", { name: list[0]?.name ?? String(target.uids[0] ?? "") });

  const object = !target ? null : target.kind === "all" ? (
    <span>
      {request?.total !== undefined
        ? t("accounts.scan.allObjectCount", { count: request.total })
        : t("accounts.scan.allObject")}
    </span>
  ) : (
    <span className="flex flex-col gap-1">
      <ul className="m-0 flex list-none flex-col gap-1 p-0">
        {list.slice(0, PREVIEW).map((a) => (
          <li key={a.uid} className="min-w-0">
            <strong className="font-semibold">
              <SafeText text={a.name} />
            </strong>{" "}
            <span className="text-ink-muted">({a.uid})</span>
            {a.home && (
              <>
                {" · "}
                <PathText path={a.home} />
              </>
            )}
          </li>
        ))}
      </ul>
      {list.length > PREVIEW && <span className="text-ink-muted">{t("accounts.scan.andMore", { count: list.length - PREVIEW })}</span>}
    </span>
  );

  return (
    <ConfirmDialog
      open={request !== null}
      onClose={onClose}
      onConfirm={async () => {
        if (!request) return;
        try {
          await mutation.mutateAsync({ target: request.target, key: request.key });
        } catch (err) {
          if (isExecutorUnavailable(err)) throw new Error(t("accounts.errors.executorScan"), { cause: err });
          throw err;
        }
      }}
      title={title}
      object={object}
      impact={target?.kind === "all" ? t("accounts.scan.allImpact") : t("accounts.scan.impact")}
      reversible
      destructive={false}
      confirmLabel={t("accounts.scan.confirm")}
    />
  );
}

/** Última verificação: estado, quando, quanto foi processado e o link para a execução. */
export function LastRunCell({ account: a }: { account: Account }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const run = a.last_run;
  if (!run) return <span className="text-ink-muted">{t("accounts.neverScanned")}</span>;
  const when = toDate(run.finished_at) ?? toDate(run.created_at);
  return (
    <span className="flex min-w-0 flex-col items-start gap-1">
      <StatusBadge kind="run" state={run.status} />
      {when && <Timestamp date={when} compact />}
      {run.files_eligible > 0 && (
        <span className="text-sm text-ink-muted tabular-nums">
          {t("accounts.processedOf", {
            processed: formatNumber(run.files_processed, lng),
            eligible: formatNumber(run.files_eligible, lng),
          })}
        </span>
      )}
      <Link to={`/execucoes/${encodeURIComponent(run.id)}`} className="text-sm font-semibold">
        {t("accounts.openRun")}
        <span className="visually-hidden"> {t("accounts.table.ofAccount", { name: a.name })}</span>
      </Link>
    </span>
  );
}
