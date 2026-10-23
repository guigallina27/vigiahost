import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleSlash, Clock, Plus, PlugZap, RefreshCw, ShieldCheck, type LucideIcon } from "lucide-react";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";
import { api, unwrap, type Schemas } from "../../api/client";
import { useCurrentUser, useReauth } from "../../auth/session";
import { Badge, type Tone } from "../../components/Badge";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";
import { Panel } from "../../components/Panel";
import { Timestamp } from "../../components/Timestamp";
import { PageHeader } from "../../layout/PageHeader";
import { formatNumber } from "../../lib/format";
import { emptyDraft, exceptionStatus, type ExceptionStatus } from "./exceptionRules";
import { ExceptionCoverage, ExceptionForm } from "./ExceptionForm";
import { StatusMessage } from "./parts";
import { TableScroll } from "../../components/TableScroll";

type Exception = Schemas["Exception"];

const statusLook: Record<ExceptionStatus, { tone: Tone; icon: LucideIcon }> = {
  active: { tone: "neutral", icon: ShieldCheck },
  revoked: { tone: "neutral", icon: CircleSlash },
  expired: { tone: "medium", icon: Clock },
};

/** Exceções (rota sugerida: /excecoes). Ativas por padrão; ?inativas=1 mostra também revogadas e vencidas. */
export function ExceptionsPage() {
  const { t, i18n } = useTranslation();
  const qc = useQueryClient();
  const { canOperate } = useCurrentUser();
  const reauth = useReauth();
  const [params, setParams] = useSearchParams();
  const showInactive = params.get("inativas") === "1";
  const [formOpen, setFormOpen] = useState(false);
  const [revoking, setRevoking] = useState<Exception | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const statusRef = useRef<HTMLParagraphElement>(null);

  const query = useQuery({
    queryKey: ["exceptions", { all: showInactive }],
    queryFn: ({ signal }) =>
      unwrap(api.GET("/api/v1/exceptions", { params: { query: showInactive ? { all: true } : {} }, signal })),
  });

  // Sem "all", o servidor já tira as revogadas; as vencidas saem aqui.
  const rows = (query.data ?? []).filter((e) => showInactive || e.active);

  function focusStatus(text: string) {
    setMessage(text);
    requestAnimationFrame(() => statusRef.current?.focus());
  }

  async function revoke(input: { password?: string; code?: string }) {
    const target = revoking;
    if (!target) return;
    await reauth.confirm(input, () =>
      unwrap(api.DELETE("/api/v1/exceptions/{id}", { params: { path: { id: target.id } } })),
    );
    for (const key of [["exceptions"], ["findings"], ["finding"], ["overview"]]) {
      void qc.invalidateQueries({ queryKey: key });
    }
    focusStatus(t("findings.exceptions.revoked", { id: target.id }));
  }

  return (
    <>
      <PageHeader
        title={t("findings.exceptions.title")}
        subtitle={t("findings.exceptions.subtitle")}
        actions={
          canOperate &&
          !formOpen && (
            <Button
              variant="primary"
              onClick={() => {
                setMessage(null);
                setFormOpen(true);
              }}
            >
              <Plus aria-hidden="true" className="size-4" />
              {t("findings.exceptions.new")}
            </Button>
          )
        }
      />

      <div className="flex flex-col gap-6">
        <StatusMessage ref={statusRef} message={message} />
        {!canOperate && <p className="m-0 text-ink-muted">{t("findings.exceptions.readOnly")}</p>}

        {formOpen && (
          <Panel title={t("findings.exceptions.formTitle")}>
            <ExceptionForm
              initial={emptyDraft()}
              onCancel={() => setFormOpen(false)}
              onCreated={(e) => {
                setFormOpen(false);
                focusStatus(t("findings.exceptions.created", { id: e.id }));
              }}
            />
          </Panel>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className="flex min-h-11 cursor-pointer items-center gap-2">
            <input
              type="checkbox"
              checked={showInactive}
              onChange={(e) => {
                const next = new URLSearchParams(params);
                if (e.target.checked) next.set("inativas", "1");
                else next.delete("inativas");
                setParams(next, { replace: true });
              }}
              className="size-4 shrink-0"
            />
            <span>{t("findings.exceptions.showInactive")}</span>
          </label>
          {query.data && (
            <p className="m-0 text-sm text-ink-muted" role="status">
              {t("findings.exceptions.count", { count: rows.length, formatted: formatNumber(rows.length, i18n.language) })}
            </p>
          )}
        </div>

        {query.isPending ? (
          <p className="m-0 text-ink-muted" role="status">
            {t("states.loading")}
          </p>
        ) : query.isError ? (
          <EmptyState
            tone="error"
            icon={PlugZap}
            title={t("findings.exceptions.errorTitle")}
            description={<p className="m-0" role="alert">{query.error.message}</p>}
            action={
              <Button variant="primary" onClick={() => void query.refetch()} disabled={query.isFetching}>
                <RefreshCw aria-hidden="true" className="size-4" />
                {t("states.retry")}
              </Button>
            }
          />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title={showInactive ? t("findings.exceptions.emptyAllTitle") : t("findings.exceptions.emptyTitle")}
            description={t("findings.exceptions.emptyDescription")}
          />
        ) : (
          <TableScroll label={t("findings.exceptions.caption")}>
            <table className="vh-table">
              <caption className="visually-hidden">{t("findings.exceptions.caption")}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("findings.exceptions.colScope")}</th>
                  <th scope="col">{t("findings.exceptions.colReason")}</th>
                  <th scope="col">{t("findings.exceptions.colCreated")}</th>
                  <th scope="col">{t("findings.exceptions.colValidity")}</th>
                  <th scope="col">{t("findings.exceptions.colStatus")}</th>
                  {canOperate && <th scope="col">{t("findings.exceptions.colActions")}</th>}
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => {
                  const status = exceptionStatus(e);
                  const look = statusLook[status];
                  return (
                    <tr key={e.id}>
                      <td className="min-w-64">
                        <span className="mb-1 block text-sm text-ink-muted tabular-nums">
                          {t("findings.exceptions.number", { id: e.id })}
                        </span>
                        <ExceptionCoverage
                          scope={e.scope}
                          sha256={e.sha256}
                          signature={e.signature}
                          pathPrefix={e.path_prefix}
                        />
                      </td>
                      <td className="min-w-56 [overflow-wrap:anywhere]">{e.reason}</td>
                      <td className="min-w-40">
                        <Timestamp date={new Date(e.created_at)} />
                        <span className="block text-sm [overflow-wrap:anywhere]">
                          {t("findings.exceptions.createdBy", { user: e.created_by })}
                        </span>
                      </td>
                      <td className="min-w-40">
                        {e.expires_at ? (
                          <Timestamp date={new Date(e.expires_at)} />
                        ) : (
                          t("findings.exceptions.noExpiry")
                        )}
                      </td>
                      <td className="min-w-36">
                        <span className="flex flex-col items-start gap-1">
                          <Badge tone={look.tone} icon={look.icon} variant="outline">
                            {t(`findings.exceptions.status.${status}`)}
                          </Badge>
                          {status === "revoked" && (
                            <span className="text-sm [overflow-wrap:anywhere]">
                              {t("findings.exceptions.revokedBy", { user: e.revoked_by })}
                              {e.revoked_at && (
                                <span className="block">
                                  <Timestamp date={new Date(e.revoked_at)} compact />
                                </span>
                              )}
                            </span>
                          )}
                        </span>
                      </td>
                      {canOperate && (
                        <td>
                          {status === "active" && (
                            <Button variant="danger" onClick={() => setRevoking(e)}>
                              {t("findings.exceptions.revoke")}
                              <span className="visually-hidden"> {t("findings.exceptions.number", { id: e.id })}</span>
                            </Button>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableScroll>
        )}
      </div>

      <ConfirmDialog
        open={revoking !== null}
        onClose={() => setRevoking(null)}
        title={t("findings.exceptions.revokeTitle")}
        object={
          revoking && (
            <ExceptionCoverage
              scope={revoking.scope}
              sha256={revoking.sha256}
              signature={revoking.signature}
              pathPrefix={revoking.path_prefix}
            />
          )
        }
        impact={t("findings.exceptions.revokeImpact")}
        reversible={false}
        confirmLabel={t("findings.exceptions.revokeLabel")}
        requireReauth
        requireCode={reauth.requireCode}
        onConfirm={revoke}
      />
    </>
  );
}
