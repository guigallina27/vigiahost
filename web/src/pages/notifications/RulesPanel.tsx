import { useMutation, useQueryClient } from "@tanstack/react-query";
import { BellOff, BellRing, CirclePause, ListPlus, Pencil, Save, Trash2 } from "lucide-react";
import type { TFunction } from "i18next";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, unwrap } from "../../api/client";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";
import { Field, FormError, SelectField } from "../../components/Field";
import { Panel } from "../../components/Panel";
import { SeverityBadge, severities } from "../../components/SeverityBadge";
import { TableScroll } from "../../components/TableScroll";
import { useGuardedAction } from "../config/useGuardedAction";
import { Checkbox } from "./ChannelForm";
import {
  buildRuleBody,
  defaultDedupMinutes,
  emptyRuleValues,
  freeEvents,
  minutesParts,
  valuesFromRule,
  type Channel,
  type Rule,
  type RuleError,
  type RuleFormValues,
  type RuleInput,
} from "./notifications";
import { notificationsKey } from "./queries";

type Editing = { mode: "new" } | { mode: "edit"; rule: Rule } | null;

/** Regras de envio: qual evento vai para qual canal, com severidade mínima (achados) e janela sem repetição. */
export function RulesPanel({ channels, rules }: { channels: readonly Channel[]; rules: readonly Rule[] }) {
  const { t } = useTranslation();
  const [editing, setEditing] = useState<Editing>(null);
  const [deleting, setDeleting] = useState<Rule | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const channelName = (id: number) => channels.find((c) => c.id === id)?.name ?? `#${id}`;
  const canAdd = channels.some((c) => freeEvents(rules, c.id).length > 0);

  return (
    <Panel
      title={t("notifications.rules.title")}
      actions={
        channels.length > 0 &&
        !editing && (
          <Button
            onClick={() => {
              setNotice(null);
              setEditing({ mode: "new" });
            }}
            disabled={!canAdd}
          >
            <ListPlus aria-hidden="true" className="size-4" />
            {t("notifications.rules.add")}
          </Button>
        )
      }
    >
      <p className="m-0 text-sm text-ink-muted">{t("notifications.rules.intro")}</p>
      <p role="status" className={notice ? "m-0 rounded-control border border-line-strong bg-accent-soft p-3" : "visually-hidden"}>
        {notice}
      </p>
      {editing && (
        <RuleForm
          key={editing.mode === "edit" ? editing.rule.id : "new"}
          channels={channels}
          rules={rules}
          {...(editing.mode === "edit" ? { editing: editing.rule } : {})}
          onCancel={() => setEditing(null)}
          onDone={(r) => {
            setEditing(null);
            setNotice(
              t(editing.mode === "edit" ? "notifications.rules.saved" : "notifications.rules.created", {
                event: t(`notifications.events.${r.event}`),
                channel: channelName(r.channel_id),
              }),
            );
          }}
        />
      )}
      {channels.length === 0 ? (
        <EmptyState
          icon={BellOff}
          headingLevel={3}
          title={t("notifications.rules.noChannelsTitle")}
          description={t("notifications.rules.noChannels")}
        />
      ) : rules.length === 0 ? (
        !editing && (
          <EmptyState
            icon={BellOff}
            headingLevel={3}
            title={t("notifications.rules.emptyTitle")}
            description={t("notifications.rules.empty")}
          />
        )
      ) : (
        <TableScroll label={t("notifications.rules.title")}>
          <table className="vh-table">
            <caption className="visually-hidden">{t("notifications.rules.caption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("notifications.rules.colChannel")}</th>
                <th scope="col">{t("notifications.rules.colEvent")}</th>
                <th scope="col">{t("notifications.rules.colSeverity")}</th>
                <th scope="col">{t("notifications.rules.colDedup")}</th>
                <th scope="col">{t("notifications.rules.colState")}</th>
                <th scope="col">{t("notifications.rules.colActions")}</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => {
                const label = `${t(`notifications.events.${r.event}`)} → ${channelName(r.channel_id)}`;
                return (
                  <tr key={r.id}>
                    <td className="[overflow-wrap:anywhere]">{channelName(r.channel_id)}</td>
                    <th scope="row" className="text-left font-normal">
                      {t(`notifications.events.${r.event}`)}
                    </th>
                    <td>
                      {r.event === "finding_new" ? (
                        <SeverityBadge severity={r.min_severity} />
                      ) : (
                        <span className="text-ink-muted">{t("notifications.rules.anySeverity")}</span>
                      )}
                    </td>
                    <td className="tabular-nums">{dedupText(r.dedup_minutes, t)}</td>
                    <td>
                      {r.enabled ? (
                        <Badge tone="low" variant="outline" icon={BellRing}>
                          {t("notifications.rules.active")}
                        </Badge>
                      ) : (
                        <Badge tone="neutral" variant="outline" icon={CirclePause}>
                          {t("notifications.rules.paused")}
                        </Badge>
                      )}
                    </td>
                    <td>
                      <div className="flex flex-wrap gap-2">
                        <Button
                          variant="ghost"
                          onClick={() => {
                            setNotice(null);
                            setEditing({ mode: "edit", rule: r });
                          }}
                        >
                          <Pencil aria-hidden="true" className="size-4" />
                          {t("notifications.rules.edit")}
                          <span className="visually-hidden">: {label}</span>
                        </Button>
                        <Button variant="ghost" onClick={() => setDeleting(r)}>
                          <Trash2 aria-hidden="true" className="size-4" />
                          {t("notifications.rules.delete")}
                          <span className="visually-hidden">: {label}</span>
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableScroll>
      )}
      <DeleteRuleDialog
        rule={deleting}
        channelName={deleting ? channelName(deleting.channel_id) : ""}
        onClose={() => setDeleting(null)}
        onDeleted={() => setNotice(t("notifications.rules.deleted"))}
      />
    </Panel>
  );
}

export function dedupText(min: number, t: TFunction): string {
  if (min === 0) return t("notifications.rules.noDedup");
  const p = minutesParts(min);
  return t(`notifications.units.${p.unit}`, { count: p.count });
}

function RuleForm({
  channels,
  rules,
  editing,
  onDone,
  onCancel,
}: {
  channels: readonly Channel[];
  rules: readonly Rule[];
  editing?: Rule;
  onDone: (r: Rule) => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const firstFree = channels.find((c) => freeEvents(rules, c.id).length > 0);
  const [values, setValues] = useState<RuleFormValues>(() => {
    if (editing) return valuesFromRule(editing);
    const v = emptyRuleValues(firstFree?.id);
    const free = firstFree ? freeEvents(rules, firstFree.id) : [];
    const first = free[0];
    if (first && !free.includes(v.event)) v.event = first;
    return v;
  });
  const [error, setError] = useState<RuleError | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [pending, setPending] = useState<RuleInput | null>(null);
  const guarded = useGuardedAction(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const headingId = useId();
  useEffect(() => headingRef.current?.focus(), []);

  const channelId = Number(values.channelId);
  const events = freeEvents(rules, channelId, editing && editing.channel_id === channelId ? editing.event : undefined);

  const save = useMutation({
    mutationFn: (body: RuleInput) =>
      editing
        ? unwrap(api.PUT("/api/v1/notifications/rules/{id}", { params: { path: { id: editing.id } }, body }))
        : unwrap(api.POST("/api/v1/notifications/rules", { body })),
  });

  function set<K extends keyof RuleFormValues>(key: K, value: RuleFormValues[K]) {
    setValues((v) => {
      const next = { ...v, [key]: value };
      if (key === "channelId") {
        const free = freeEvents(rules, Number(value), editing?.event);
        const first = free[0];
        if (first && !free.includes(next.event)) next.event = first;
      }
      return next;
    });
    setError(null);
  }

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError(null);
    const built = buildRuleBody(values);
    if (!built.ok) {
      setError(built.error);
      return;
    }
    setPending(built.body);
  }

  async function confirm(input: { password?: string; code?: string }) {
    if (!pending) return;
    let saved: Rule | undefined;
    try {
      await guarded.run(input, async () => {
        saved = await save.mutateAsync(pending);
      });
    } catch (e) {
      if (e instanceof ApiError && (e.status === 400 || e.status === 409)) {
        setFormError(e.message);
        return;
      }
      throw e;
    }
    await qc.invalidateQueries({ queryKey: notificationsKey });
    if (saved) onDone(saved);
  }

  const channelName = channels.find((c) => c.id === channelId)?.name ?? "";

  return (
    <section aria-labelledby={headingId} className="flex min-w-0 flex-col gap-4 rounded-control border border-line-strong p-4">
      <h3 id={headingId} ref={headingRef} tabIndex={-1} className="m-0 text-lg font-bold">
        {editing ? t("notifications.rules.editTitle") : t("notifications.rules.newTitle")}
      </h3>
      <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
        <FormError message={formError} />
        <div className="grid gap-4 md:grid-cols-2">
          <SelectField
            label={t("notifications.rules.channel")}
            options={channels.map((c) => ({ value: String(c.id), label: c.name }))}
            value={values.channelId}
            onChange={(e) => set("channelId", e.target.value)}
            error={error === "channelRequired" ? t("notifications.rules.errors.channelRequired") : null}
          />
          <SelectField
            label={t("notifications.rules.event")}
            hint={t(`notifications.eventHelp.${values.event}`)}
            options={events.map((ev) => ({ value: ev, label: t(`notifications.events.${ev}`) }))}
            value={values.event}
            onChange={(e) => set("event", e.target.value as RuleFormValues["event"])}
          />
          {values.event === "finding_new" && (
            <SelectField
              label={t("notifications.rules.minSeverity")}
              hint={t("notifications.rules.minSeverityHint")}
              options={severities.map((s) => ({ value: s, label: t(`severity.${s}`) }))}
              value={values.minSeverity}
              onChange={(e) => set("minSeverity", e.target.value as RuleFormValues["minSeverity"])}
            />
          )}
          <Field
            label={t("notifications.rules.dedup")}
            hint={t("notifications.rules.dedupHint", { value: dedupText(defaultDedupMinutes(values.event), t) })}
            value={values.dedupMinutes}
            onChange={(e) => set("dedupMinutes", e.target.value)}
            inputMode="numeric"
            maxLength={5}
            autoComplete="off"
            error={error === "dedupInvalid" ? t("notifications.rules.errors.dedupInvalid") : null}
          />
        </div>
        <Checkbox
          label={t("notifications.rules.enabled")}
          hint={t("notifications.rules.enabledHint")}
          checked={values.enabled}
          onChange={(v) => set("enabled", v)}
        />
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="secondary" onClick={onCancel}>
            {t("notifications.form.cancel")}
          </Button>
          <Button type="submit" variant="primary" disabled={save.isPending}>
            <Save aria-hidden="true" className="size-4" />
            {t("notifications.rules.save")}
          </Button>
        </div>
      </form>
      <ConfirmDialog
        open={pending !== null}
        onClose={() => {
          guarded.reset();
          setPending(null);
        }}
        onConfirm={confirm}
        title={editing ? t("notifications.rules.confirmEditTitle") : t("notifications.rules.confirmNewTitle")}
        object={
          <span className="[overflow-wrap:anywhere]">
            {t(`notifications.events.${values.event}`)} → {channelName}
          </span>
        }
        impact={values.enabled ? t("notifications.rules.confirmImpact") : t("notifications.rules.confirmImpactPaused")}
        reversible
        destructive={false}
        requireReauth={guarded.requireReauth}
        requireCode={guarded.requireCode}
        confirmLabel={t("notifications.rules.save")}
      />
    </section>
  );
}

function DeleteRuleDialog({
  rule,
  channelName,
  onClose,
  onDeleted,
}: {
  rule: Rule | null;
  channelName: string;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const guarded = useGuardedAction(false);
  return (
    <ConfirmDialog
      open={rule !== null}
      onClose={() => {
        guarded.reset();
        onClose();
      }}
      onConfirm={async (input) => {
        if (!rule) return;
        try {
          await guarded.run(input, () =>
            unwrap(api.DELETE("/api/v1/notifications/rules/{id}", { params: { path: { id: rule.id } } })),
          );
        } catch (err) {
          if (!(err instanceof ApiError && err.status === 404)) throw err;
        }
        await qc.invalidateQueries({ queryKey: notificationsKey });
        onDeleted();
      }}
      title={t("notifications.rules.deleteTitle")}
      object={
        rule && (
          <span className="[overflow-wrap:anywhere]">
            {t(`notifications.events.${rule.event}`)} → {channelName}
          </span>
        )
      }
      impact={t("notifications.rules.deleteImpact")}
      reversible={false}
      requireReauth={guarded.requireReauth}
      requireCode={guarded.requireCode}
      confirmLabel={t("notifications.rules.deleteConfirm")}
    />
  );
}
