import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleCheck, CircleSlash, Eye, EyeOff, Lock, PlugZap, RefreshCw, ShieldAlert, ShieldCheck, UserPlus, Users, Wand2 } from "lucide-react";
import { useId, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, sessionQuery, unwrap } from "../../api/client";
import { useCurrentUser } from "../../auth/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { Field, FormError, SelectField } from "../../components/Field";
import { Panel } from "../../components/Panel";
import { Timestamp } from "../../components/Timestamp";
import { PageHeader } from "../../layout/PageHeader";
import {
  buildUserUpdate,
  checkPassword,
  checkUsername,
  generatePassword,
  roles,
  updateEndsSessions,
  updateRemovesLastAdmin,
  userGuard,
  type Role,
  type User,
  type UserUpdate,
} from "./adminLogic";
import { SafeText, SecretOnce } from "./SecretOnce";
import { useSensitiveAction } from "./SensitiveDialog";
import { TableScroll } from "../../components/TableScroll";

export const usersQueryKey = ["users"] as const;

/** Usuários do painel (só administrador): criar, editar perfil/nome/bloqueio, redefinir segundo fator e remover. */
export function UsersPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { isAdmin, user: me } = useCurrentUser();
  const users = useQuery({
    queryKey: usersQueryKey,
    queryFn: ({ signal }) => unwrap(api.GET("/api/v1/users", { signal })),
    enabled: isAdmin,
  });
  const sensitive = useSensitiveAction();
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<{ username: string; password: string } | null>(null);
  const [editing, setEditing] = useState<User | null>(null);

  async function refresh() {
    await Promise.all([
      qc.invalidateQueries({ queryKey: usersQueryKey }),
      // O próprio perfil pode ter mudado (ou a sessão, sido encerrada).
      qc.invalidateQueries({ queryKey: sessionQuery.queryKey }),
    ]);
  }

  if (!isAdmin) {
    return (
      <>
        <PageHeader title={t("admin.users.title")} subtitle={t("admin.users.subtitle")} />
        <EmptyState icon={Lock} title={t("admin.common.forbiddenTitle")} description={t("admin.users.forbidden")} />
      </>
    );
  }

  const list = users.data ?? [];

  function askCreate(input: NewUser) {
    sensitive.ask({
      title: t("admin.users.confirmCreateTitle"),
      object: (
        <span className="grid gap-0.5">
          <SafeText value={input.username} mono />
          <span className="text-sm text-ink-muted">{t(`roles.${input.role}`)}</span>
        </span>
      ),
      impact: t("admin.users.confirmCreateImpact", { role: t(`roles.${input.role}`) }),
      reversible: true,
      confirmLabel: t("admin.users.confirmCreate"),
      destructive: false,
      run: async () => {
        const user = await unwrap(
          api.POST("/api/v1/users", {
            body: {
              username: input.username,
              role: input.role,
              password: input.password,
              ...(input.displayName ? { display_name: input.displayName } : {}),
            },
          }),
        );
        setCreating(false);
        setCreated({ username: user.username, password: input.password });
        await refresh();
      },
    });
  }

  function askUpdate(target: User, body: UserUpdate) {
    const endsSessions = updateEndsSessions(target, body);
    sensitive.ask({
      title: t("admin.users.confirmUpdateTitle", { username: target.username }),
      object: <ChangeList user={target} body={body} />,
      impact: [
        endsSessions ? t("admin.users.impactSessions") : t("admin.users.impactNameOnly"),
        endsSessions && target.id === me?.id ? t("admin.users.impactSelf") : "",
      ]
        .filter(Boolean)
        .join(" "),
      reversible: true,
      confirmLabel: t("admin.users.save"),
      destructive: endsSessions,
      run: async () => {
        await unwrap(api.PATCH("/api/v1/users/{id}", { params: { path: { id: target.id } }, body }));
        setEditing(null);
        await refresh();
      },
    });
  }

  function askResetMfa(target: User) {
    sensitive.ask({
      title: t("admin.users.confirmResetMfaTitle"),
      object: <SafeText value={target.username} mono />,
      impact: t("admin.users.confirmResetMfaImpact"),
      reversible: false,
      confirmLabel: t("admin.users.confirmResetMfa"),
      run: async () => {
        await unwrap(api.POST("/api/v1/users/{id}/mfa-reset", { params: { path: { id: target.id } } }));
        await refresh();
      },
    });
  }

  function askDelete(target: User) {
    sensitive.ask({
      title: t("admin.users.confirmDeleteTitle"),
      object: (
        <span className="grid gap-0.5">
          <SafeText value={target.username} mono />
          {target.display_name && <SafeText value={target.display_name} />}
        </span>
      ),
      impact: t("admin.users.confirmDeleteImpact"),
      reversible: false,
      confirmLabel: t("admin.users.confirmDelete"),
      run: async () => {
        await unwrap(api.DELETE("/api/v1/users/{id}", { params: { path: { id: target.id } } }));
        if (editing?.id === target.id) setEditing(null);
        await refresh();
      },
    });
  }

  return (
    <>
      <PageHeader
        title={t("admin.users.title")}
        subtitle={t("admin.users.subtitle")}
        actions={
          !creating && (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <UserPlus aria-hidden="true" className="size-4" />
              {t("admin.users.create")}
            </Button>
          )
        }
      />
      <div className="flex flex-col gap-6">
        {created && (
          <SecretOnce
            title={t("admin.users.createdTitle", { username: created.username })}
            label={t("admin.users.createdLabel", { username: created.username })}
            value={created.password}
            warning={t("admin.users.createdWarning")}
            doneLabel={t("admin.users.createdDone")}
            onDone={() => setCreated(null)}
          >
            <p className="m-0 text-ink-muted">{t("admin.users.createdMfa")}</p>
          </SecretOnce>
        )}

        {creating && <CreateUserForm onCancel={() => setCreating(false)} onSubmit={askCreate} />}

        {editing && (
          <EditUserForm
            key={editing.id}
            user={editing}
            users={list}
            selfId={me?.id}
            onCancel={() => setEditing(null)}
            onSubmit={(body) => askUpdate(editing, body)}
          />
        )}

        <Panel
          title={t("admin.users.listCaption")}
          actions={users.data && <span className="text-sm text-ink-muted">{t("admin.users.count", { count: list.length })}</span>}
        >
          {users.isPending ? (
            <p className="m-0 text-ink-muted">{t("states.loading")}</p>
          ) : users.isError ? (
            <EmptyState
              tone="error"
              icon={PlugZap}
              headingLevel={3}
              title={t("admin.common.loadErrorTitle")}
              description={users.error.message}
              action={
                <Button onClick={() => void users.refetch()} disabled={users.isFetching}>
                  <RefreshCw aria-hidden="true" className="size-4" />
                  {t("states.retry")}
                </Button>
              }
            />
          ) : list.length === 0 ? (
            <EmptyState icon={Users} headingLevel={3} title={t("admin.users.title")} description={t("admin.users.empty")} />
          ) : (
            <UsersTable users={list} selfId={me?.id} onEdit={setEditing} onResetMfa={askResetMfa} onDelete={askDelete} />
          )}
        </Panel>
      </div>
      {sensitive.dialog}
    </>
  );
}

type NewUser = { username: string; displayName: string; role: Role; password: string };

function useRoleOptions() {
  const { t } = useTranslation();
  return roles.map((r) => ({ value: r, label: `${t(`roles.${r}`)} — ${t(`admin.roleHelp.${r}`)}` }));
}

/** Formulário de novo usuário: valida no cliente as mesmas regras do servidor antes de pedir a confirmação. */
function CreateUserForm({ onCancel, onSubmit }: { onCancel: () => void; onSubmit: (input: NewUser) => void }) {
  const { t } = useTranslation();
  const roleOptions = useRoleOptions();
  const [form, setForm] = useState<NewUser>({ username: "", displayName: "", role: "reader", password: "" });
  const [errors, setErrors] = useState<{ username?: string; password?: string }>({});

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const username = form.username.trim();
    const next: { username?: string; password?: string } = {};
    if (!checkUsername(username)) next.username = t("admin.users.usernameInvalid");
    const pw = checkPassword(form.password);
    if (pw) next.password = pw === "short" ? t("admin.common.passwordShort") : t("admin.common.passwordLong");
    setErrors(next);
    if (next.username || next.password) return;
    onSubmit({ ...form, username, displayName: form.displayName.trim() });
  }

  return (
    <Panel title={t("admin.users.createTitle")}>
      <form onSubmit={submit} noValidate className="grid gap-4 md:grid-cols-2">
        <Field
          label={t("admin.users.username")}
          hint={t("admin.users.usernameHint")}
          error={errors.username ?? null}
          value={form.username}
          onChange={(e) => setForm({ ...form, username: e.target.value })}
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          maxLength={64}
          required
          mono
        />
        <Field
          label={t("admin.users.displayName")}
          hint={t("admin.users.displayNameHint")}
          value={form.displayName}
          onChange={(e) => setForm({ ...form, displayName: e.target.value })}
          autoComplete="off"
          maxLength={128}
        />
        <SelectField
          className="md:col-span-2"
          label={t("admin.users.role")}
          hint={t("admin.users.mfaNotice")}
          options={roleOptions}
          value={form.role}
          onChange={(e) => setForm({ ...form, role: e.target.value as Role })}
        />
        <PasswordWithGenerator
          value={form.password}
          error={errors.password ?? null}
          onChange={(password) => setForm({ ...form, password })}
        />
        <div className="flex flex-wrap gap-2 md:col-span-2">
          <Button type="submit" variant="primary">
            <UserPlus aria-hidden="true" className="size-4" />
            {t("admin.users.create")}
          </Button>
          <Button onClick={onCancel}>{t("admin.common.cancel")}</Button>
        </div>
      </form>
    </Panel>
  );
}

/** Senha inicial com botão de gerar (aleatória, sem caracteres ambíguos) e de mostrar/ocultar. */
function PasswordWithGenerator({
  value,
  error,
  onChange,
}: {
  value: string;
  error: string | null;
  onChange: (value: string) => void;
}) {
  const { t } = useTranslation();
  const [visible, setVisible] = useState(false);
  return (
    <div className="grid min-w-0 gap-2 md:col-span-2">
      <Field
        label={t("admin.users.password")}
        hint={t("admin.users.passwordHint")}
        error={error}
        type={visible ? "text" : "password"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete="new-password"
        spellCheck={false}
        required
        mono
      />
      <div className="flex flex-wrap gap-2">
        <Button
          onClick={() => {
            onChange(generatePassword());
            setVisible(true);
          }}
        >
          <Wand2 aria-hidden="true" className="size-4" />
          {t("admin.users.generatePassword")}
        </Button>
        <Button variant="ghost" aria-pressed={visible} onClick={() => setVisible(!visible)}>
          {visible ? <EyeOff aria-hidden="true" className="size-4" /> : <Eye aria-hidden="true" className="size-4" />}
          {visible ? t("admin.common.hidePassword") : t("admin.common.showPassword")}
        </Button>
      </div>
    </div>
  );
}

/** Edição de nome, perfil e bloqueio; protege o último administrador habilitado antes de chegar ao servidor. */
function EditUserForm({
  user,
  users,
  selfId,
  onCancel,
  onSubmit,
}: {
  user: User;
  users: readonly User[];
  selfId: number | undefined;
  onCancel: () => void;
  onSubmit: (body: UserUpdate) => void;
}) {
  const { t } = useTranslation();
  const roleOptions = useRoleOptions();
  const guard = userGuard(user, users, selfId);
  const [displayName, setDisplayName] = useState(user.display_name);
  const [role, setRole] = useState<Role>(user.role);
  const [disabled, setDisabled] = useState(user.disabled);
  const [error, setError] = useState<string | null>(null);
  const disabledId = useId();
  const disabledHintId = useId();
  const guardId = useId();

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const body = buildUserUpdate(user, { display_name: displayName, role, disabled });
    if (!body) {
      setError(t("admin.common.nothingChanged"));
      return;
    }
    if (updateRemovesLastAdmin(user, body, users)) {
      setError(t("admin.users.lastAdminError"));
      return;
    }
    setError(null);
    onSubmit(body);
  }

  return (
    <Panel title={t("admin.users.editTitle", { username: user.username })}>
      <form onSubmit={submit} noValidate className="grid gap-4 md:grid-cols-2">
        {guard.lastAdmin && (
          <p id={guardId} className="m-0 flex items-start gap-2 rounded-control bg-(--vh-medium-bg) p-3 text-(--vh-medium-fg) md:col-span-2">
            <ShieldAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
            <span className="min-w-0">{t("admin.users.lastAdminHint")}</span>
          </p>
        )}
        <Field
          label={t("admin.users.displayName")}
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          autoComplete="off"
          maxLength={128}
        />
        <SelectField
          label={t("admin.users.role")}
          options={roleOptions}
          value={role}
          onChange={(e) => setRole(e.target.value as Role)}
          disabled={guard.lastAdmin}
          aria-describedby={guard.lastAdmin ? guardId : undefined}
        />
        <div className="flex items-start gap-3 md:col-span-2">
          <input
            id={disabledId}
            type="checkbox"
            checked={disabled}
            onChange={(e) => setDisabled(e.target.checked)}
            disabled={guard.lastAdmin}
            aria-describedby={guard.lastAdmin ? `${disabledHintId} ${guardId}` : disabledHintId}
            className="mt-1 size-5 shrink-0"
          />
          <span className="grid min-w-0 gap-0.5">
            <label htmlFor={disabledId} className="font-semibold">
              {t("admin.users.disabledField")}
            </label>
            <span id={disabledHintId} className="text-sm text-ink-muted">
              {t("admin.users.disabledHint")}
            </span>
          </span>
        </div>
        <div className="md:col-span-2">
          <FormError message={error} />
        </div>
        <div className="flex flex-wrap gap-2 md:col-span-2">
          <Button type="submit" variant="primary">
            {t("admin.users.save")}
          </Button>
          <Button onClick={onCancel}>{t("admin.common.cancel")}</Button>
        </div>
      </form>
    </Panel>
  );
}

/** Resumo do que muda, mostrado como objeto da confirmação. */
function ChangeList({ user, body }: { user: User; body: UserUpdate }) {
  const { t } = useTranslation();
  const items: string[] = [];
  if (body.display_name !== undefined) {
    items.push(t("admin.users.changeName", { from: user.display_name || "—", to: body.display_name || "—" }));
  }
  if (body.role !== undefined) {
    items.push(t("admin.users.changeRole", { from: t(`roles.${user.role}`), to: t(`roles.${body.role}`) }));
  }
  if (body.disabled !== undefined) items.push(body.disabled ? t("admin.users.changeDisable") : t("admin.users.changeEnable"));
  return (
    <span className="grid gap-1">
      <SafeText value={user.username} mono />
      <ul className="m-0 grid gap-0.5 ps-5 text-sm">
        {items.map((item) => (
          <li key={item}>
            <SafeText value={item} />
          </li>
        ))}
      </ul>
    </span>
  );
}

function UsersTable({
  users,
  selfId,
  onEdit,
  onResetMfa,
  onDelete,
}: {
  users: readonly User[];
  selfId: number | undefined;
  onEdit: (u: User) => void;
  onResetMfa: (u: User) => void;
  onDelete: (u: User) => void;
}) {
  const { t } = useTranslation();
  return (
    <TableScroll label={t("admin.users.listCaption")}>
      <table className="vh-table">
        <caption className="visually-hidden">{t("admin.users.listCaption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("admin.users.colName")}</th>
            <th scope="col">{t("admin.users.colRole")}</th>
            <th scope="col">{t("admin.users.colMfa")}</th>
            <th scope="col">{t("admin.users.colLastLogin")}</th>
            <th scope="col">{t("admin.users.colStatus")}</th>
            <th scope="col">{t("admin.common.actions")}</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => {
            const guard = userGuard(u, users, selfId);
            return (
              <tr key={u.id}>
                <th scope="row" className="min-w-40 text-left font-normal">
                  <span className="grid gap-0.5">
                    <span className="font-semibold">
                      <SafeText value={u.display_name || u.username} />
                    </span>
                    <span className="text-sm text-ink-muted">
                      <SafeText value={u.username} mono />
                    </span>
                    {guard.isSelf && <span className="text-sm font-semibold text-ink-muted">({t("admin.common.you")})</span>}
                  </span>
                </th>
                <td>{t(`roles.${u.role}`)}</td>
                <td>
                  {u.mfa_enabled ? (
                    <Badge tone="ok" variant="outline" icon={ShieldCheck}>
                      {t("admin.users.mfaOn")}
                    </Badge>
                  ) : (
                    <Badge tone="medium" variant="outline" icon={ShieldAlert}>
                      {t("admin.users.mfaOff")}
                    </Badge>
                  )}
                </td>
                <td>{u.last_login_at ? <Timestamp date={new Date(u.last_login_at)} compact /> : t("admin.common.never")}</td>
                <td>
                  {u.disabled ? (
                    <Badge tone="neutral" variant="outline" icon={CircleSlash}>
                      {t("admin.users.disabled")}
                    </Badge>
                  ) : (
                    <Badge tone="ok" variant="outline" icon={CircleCheck}>
                      {t("admin.users.enabled")}
                    </Badge>
                  )}
                </td>
                <td>
                  <div className="flex min-w-56 flex-wrap gap-2">
                    <Button variant="secondary" onClick={() => onEdit(u)} aria-label={t("admin.users.edit", { username: u.username })}>
                      {t("admin.users.editShort")}
                    </Button>
                    {u.mfa_enabled && (
                      <Button
                        variant="secondary"
                        onClick={() => onResetMfa(u)}
                        aria-label={t("admin.users.resetMfa", { username: u.username })}
                      >
                        {t("admin.users.resetMfaShort")}
                      </Button>
                    )}
                    {guard.canDelete ? (
                      <Button variant="danger" onClick={() => onDelete(u)} aria-label={t("admin.users.delete", { username: u.username })}>
                        {t("admin.users.deleteShort")}
                      </Button>
                    ) : (
                      <span className="text-sm text-ink-muted">
                        {guard.isSelf ? t("admin.users.selfDeleteHint") : t("admin.users.lastAdminHint")}
                      </span>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </TableScroll>
  );
}
