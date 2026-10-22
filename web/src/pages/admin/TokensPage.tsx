import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleCheck, CircleSlash, Clock, KeyRound, Plus, PlugZap, RefreshCw } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { Field, SelectField } from "../../components/Field";
import { Panel } from "../../components/Panel";
import { Timestamp } from "../../components/Timestamp";
import { PageHeader } from "../../layout/PageHeader";
import { issuableRoles, parseTokenDays, tokenStatus, type ApiToken, type Role } from "./adminLogic";
import { SafeText, SecretOnce } from "./SecretOnce";
import { useSensitiveAction } from "./SensitiveDialog";

export const tokensQueryKey = ["tokens"] as const;

/** Tokens de API: cada pessoa vê e revoga os próprios; o administrador vê e revoga todos. */
export function TokensPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { user, isAdmin } = useCurrentUser();
  const tokens = useQuery({
    queryKey: tokensQueryKey,
    queryFn: ({ signal }) => unwrap(api.GET("/api/v1/tokens", { signal })),
  });
  const sensitive = useSensitiveAction();
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<{ name: string; token: string } | null>(null);
  // Momento da última leitura, para classificar expirados sem chamar Date.now() durante a renderização.
  const now = tokens.dataUpdatedAt;
  const list = tokens.data ?? [];

  async function refresh() {
    await qc.invalidateQueries({ queryKey: tokensQueryKey });
  }

  function askCreate(input: { name: string; role: Role; days: number }) {
    sensitive.ask({
      title: t("admin.tokens.confirmCreateTitle"),
      object: (
        <span className="grid gap-0.5">
          <SafeText value={input.name} />
          <span className="text-sm text-ink-muted">{t(`roles.${input.role}`)}</span>
        </span>
      ),
      impact: t("admin.tokens.confirmCreateImpact", { role: t(`roles.${input.role}`), count: input.days }),
      reversible: true,
      confirmLabel: t("admin.tokens.confirmCreate"),
      destructive: false,
      run: async () => {
        const res = await unwrap(
          api.POST("/api/v1/tokens", { body: { name: input.name, role: input.role, expires_in_days: input.days } }),
        );
        setCreating(false);
        setCreated({ name: res.info.name, token: res.token });
        await refresh();
      },
    });
  }

  function askRevoke(token: ApiToken) {
    sensitive.ask({
      title: t("admin.tokens.confirmRevokeTitle"),
      object: (
        <span className="grid gap-0.5">
          <SafeText value={token.name} />
          <span className="text-sm text-ink-muted">
            <SafeText value={t("admin.tokens.prefix", { prefix: `${token.prefix}…` })} mono />
          </span>
        </span>
      ),
      impact: t("admin.tokens.confirmRevokeImpact"),
      reversible: false,
      confirmLabel: t("admin.tokens.confirmRevoke"),
      run: async () => {
        await unwrap(api.DELETE("/api/v1/tokens/{id}", { params: { path: { id: token.id } } }));
        await refresh();
      },
    });
  }

  return (
    <>
      <PageHeader
        title={t("admin.tokens.title")}
        subtitle={t("admin.tokens.subtitle")}
        actions={
          !creating && (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus aria-hidden="true" className="size-4" />
              {t("admin.tokens.create")}
            </Button>
          )
        }
      />
      <div className="flex flex-col gap-6">
        {created && (
          <SecretOnce
            title={t("admin.tokens.createdTitle", { name: created.name })}
            label={t("admin.tokens.createdLabel")}
            value={created.token}
            warning={t("admin.tokens.createdWarning")}
            doneLabel={t("admin.tokens.createdDone")}
            onDone={() => setCreated(null)}
          />
        )}

        {creating && (
          <CreateTokenForm role={user?.role} onCancel={() => setCreating(false)} onSubmit={askCreate} />
        )}

        <Panel
          title={t("admin.tokens.listCaption")}
          actions={tokens.data && <span className="text-sm text-ink-muted">{t("admin.tokens.count", { count: list.length })}</span>}
        >
          <p className="m-0 text-sm text-ink-muted">{isAdmin ? t("admin.tokens.allUsers") : t("admin.tokens.ownOnly")}</p>
          {tokens.isPending ? (
            <p className="m-0 text-ink-muted">{t("states.loading")}</p>
          ) : tokens.isError ? (
            <EmptyState
              tone="error"
              icon={PlugZap}
              headingLevel={3}
              title={t("admin.common.loadErrorTitle")}
              description={tokens.error.message}
              action={
                <Button onClick={() => void tokens.refetch()} disabled={tokens.isFetching}>
                  <RefreshCw aria-hidden="true" className="size-4" />
                  {t("states.retry")}
                </Button>
              }
            />
          ) : list.length === 0 ? (
            <EmptyState icon={KeyRound} headingLevel={3} title={t("admin.tokens.title")} description={t("admin.tokens.empty")} />
          ) : (
            <TokensTable tokens={list} now={now} onRevoke={askRevoke} />
          )}
        </Panel>

        <TokenUsage />
      </div>
      {sensitive.dialog}
    </>
  );
}

function CreateTokenForm({
  role,
  onCancel,
  onSubmit,
}: {
  role: Role | undefined;
  onCancel: () => void;
  onSubmit: (input: { name: string; role: Role; days: number }) => void;
}) {
  const { t } = useTranslation();
  const allowed = issuableRoles(role);
  const [name, setName] = useState("");
  const [tokenRole, setTokenRole] = useState<Role>(allowed.includes("reader") ? "reader" : (allowed[0] ?? "reader"));
  const [days, setDays] = useState("90");
  const [errors, setErrors] = useState<{ name?: string; days?: string }>({});

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const trimmed = name.trim();
    const parsed = parseTokenDays(days);
    const next: { name?: string; days?: string } = {};
    if (!trimmed || trimmed.length > 64) next.name = t("admin.tokens.nameRequired");
    if (parsed === null) next.days = t("admin.tokens.daysInvalid");
    setErrors(next);
    if (next.name || next.days || parsed === null) return;
    onSubmit({ name: trimmed, role: tokenRole, days: parsed });
  }

  return (
    <Panel title={t("admin.tokens.createTitle")}>
      <form onSubmit={submit} noValidate className="grid gap-4 md:grid-cols-2">
        <Field
          className="md:col-span-2"
          label={t("admin.tokens.name")}
          hint={t("admin.tokens.nameHint")}
          error={errors.name ?? null}
          value={name}
          onChange={(e) => setName(e.target.value)}
          autoComplete="off"
          maxLength={64}
          required
        />
        <SelectField
          label={t("admin.tokens.role")}
          hint={t("admin.tokens.roleHint")}
          options={allowed.map((r) => ({ value: r, label: `${t(`roles.${r}`)} — ${t(`admin.roleHelp.${r}`)}` }))}
          value={tokenRole}
          onChange={(e) => setTokenRole(e.target.value as Role)}
        />
        <Field
          label={t("admin.tokens.days")}
          hint={t("admin.tokens.daysHint")}
          error={errors.days ?? null}
          value={days}
          onChange={(e) => setDays(e.target.value)}
          type="number"
          inputMode="numeric"
          min={1}
          max={365}
          step={1}
          required
        />
        <div className="flex flex-wrap gap-2 md:col-span-2">
          <Button type="submit" variant="primary">
            <Plus aria-hidden="true" className="size-4" />
            {t("admin.tokens.create")}
          </Button>
          <Button onClick={onCancel}>{t("admin.common.cancel")}</Button>
        </div>
      </form>
    </Panel>
  );
}

function TokensTable({ tokens, now, onRevoke }: { tokens: readonly ApiToken[]; now: number; onRevoke: (t: ApiToken) => void }) {
  const { t } = useTranslation();
  return (
    <div className="vh-table-wrap">
      <table className="vh-table">
        <caption className="visually-hidden">{t("admin.tokens.listCaption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("admin.tokens.colName")}</th>
            <th scope="col">{t("admin.tokens.colRole")}</th>
            <th scope="col">{t("admin.tokens.colOwner")}</th>
            <th scope="col">{t("admin.tokens.colCreated")}</th>
            <th scope="col">{t("admin.tokens.colLastUsed")}</th>
            <th scope="col">{t("admin.tokens.colExpires")}</th>
            <th scope="col">{t("admin.tokens.colStatus")}</th>
            <th scope="col">{t("admin.common.actions")}</th>
          </tr>
        </thead>
        <tbody>
          {tokens.map((tk) => {
            const status = tokenStatus(tk, now);
            return (
              <tr key={tk.id}>
                <th scope="row" className="min-w-40 text-left font-normal">
                  <span className="grid gap-0.5">
                    <span className="font-semibold">
                      <SafeText value={tk.name} />
                    </span>
                    <span className="text-sm text-ink-muted">
                      <SafeText value={t("admin.tokens.prefix", { prefix: `${tk.prefix}…` })} mono />
                    </span>
                  </span>
                </th>
                <td>{t(`roles.${tk.role}`)}</td>
                <td>
                  <SafeText value={tk.username} mono />
                </td>
                <td>
                  <Timestamp date={new Date(tk.created_at)} compact />
                </td>
                <td>{tk.last_used ? <Timestamp date={new Date(tk.last_used)} compact /> : t("admin.common.never")}</td>
                <td>
                  <Timestamp date={new Date(tk.expires_at)} compact />
                </td>
                <td>
                  <TokenStatusBadge status={status} />
                  {status === "revoked" && tk.revoked_at && (
                    <span className="mt-1 block">
                      <Timestamp date={new Date(tk.revoked_at)} compact />
                    </span>
                  )}
                </td>
                <td>
                  {status === "active" && (
                    <Button variant="danger" onClick={() => onRevoke(tk)} aria-label={t("admin.tokens.revoke", { name: tk.name })}>
                      {t("admin.tokens.revokeShort")}
                    </Button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function TokenStatusBadge({ status }: { status: ReturnType<typeof tokenStatus> }) {
  const { t } = useTranslation();
  if (status === "active") {
    return (
      <Badge tone="ok" variant="outline" icon={CircleCheck}>
        {t("admin.tokens.statusActive")}
      </Badge>
    );
  }
  if (status === "expired") {
    return (
      <Badge tone="neutral" variant="outline" icon={Clock}>
        {t("admin.tokens.statusExpired")}
      </Badge>
    );
  }
  return (
    <Badge tone="neutral" variant="outline" icon={CircleSlash}>
      {t("admin.tokens.statusRevoked")}
    </Badge>
  );
}

/** Como usar o token: cabeçalho Authorization e um exemplo com o endereço deste painel. */
function TokenUsage() {
  const { t } = useTranslation();
  const origin = globalThis.location?.origin ?? "https://painel.exemplo";
  const header = "Authorization: Bearer <token>";
  const example = `curl -H "${header}" ${origin}/api/v1/overview`;
  return (
    <Panel title={t("admin.tokens.usageTitle")}>
      <p className="m-0">{t("admin.tokens.usageHeader")}</p>
      <pre className="m-0 rounded-control bg-sunken p-3 font-mono text-sm whitespace-pre-wrap [overflow-wrap:anywhere]" translate="no">
        <code>{header}</code>
      </pre>
      <p className="m-0">{t("admin.tokens.usageExample")}</p>
      <pre className="m-0 rounded-control bg-sunken p-3 font-mono text-sm whitespace-pre-wrap [overflow-wrap:anywhere]" translate="no">
        <code>{example}</code>
      </pre>
      <p className="m-0 text-sm text-ink-muted">{t("admin.tokens.usageLimit")}</p>
    </Panel>
  );
}
