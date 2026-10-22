import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api, unwrap, type Schemas } from "../../api/client";
import { useReauth } from "../../auth/session";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { FormError } from "../../components/Field";
import { StatusBadge } from "../../components/StatusBadge";
import { FieldError, NoteField, StatusMessage } from "./parts";
import { buildTransition, manualTargets, noteRequired } from "./transitions";

type FindingDetail = Schemas["FindingDetail"];
type FindingState = Schemas["FindingState"];
type TransitionBody = Schemas["FindingTransition"];

const radioLabel =
  "flex min-h-11 cursor-pointer items-center gap-3 rounded-control border border-line-strong bg-surface px-3 py-2 has-checked:border-accent has-checked:bg-accent-soft has-focus-visible:outline-3 has-focus-visible:outline-offset-2 has-focus-visible:outline-(--vh-focus)";

/**
 * Mudança manual de estado do achado. As opções vêm de allowed_transitions (o servidor já filtra por estado
 * e perfil); falso positivo e resolvido pedem nota.
 */
export function TransitionForm({ detail, queryKey }: { detail: FindingDetail; queryKey: readonly unknown[] }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const reauth = useReauth();
  const choiceErrorId = useId();
  const formRef = useRef<HTMLFormElement>(null);
  const [to, setTo] = useState<FindingState | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState<"chooseState" | "noteMissing" | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [done, setDone] = useState<string | null>(null);
  const [pendingReauth, setPendingReauth] = useState<TransitionBody | null>(null);
  const id = detail.finding.id;
  const targets = manualTargets(detail.allowed_transitions);

  const send = (body: TransitionBody) =>
    unwrap(api.POST("/api/v1/findings/{findingId}/transition", { params: { path: { findingId: id } }, body }));

  function applied(data: FindingDetail, body: TransitionBody) {
    qc.setQueryData(queryKey, data);
    void qc.invalidateQueries({ queryKey: ["findings"] });
    void qc.invalidateQueries({ queryKey: ["overview"] });
    setDone(t("findings.transition.done", { state: t(`findingState.${body.to}`) }));
    setTo(null);
    setNote("");
  }

  const mutation = useMutation({
    mutationFn: send,
    onSuccess: applied,
    onError: (err, body) => {
      // A rota não pede reautenticação hoje; se o servidor passar a pedir, a tela se adapta.
      if (err instanceof ApiError && err.code === "reauth_required") setPendingReauth(body);
    },
  });

  // Depois de uma tentativa inválida, o foco vai para o primeiro campo com problema.
  useEffect(() => {
    if (attempt === 0) return;
    formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"], [data-invalid="true"] input')?.focus();
  }, [attempt]);

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setDone(null);
    const check = buildTransition(to, note);
    if (!check.ok) {
      setError(check.error);
      setAttempt((n) => n + 1);
      return;
    }
    setError(null);
    mutation.mutate(check.body);
  }

  if (targets.length === 0) {
    return (
      <div className="flex flex-col gap-3">
        <StatusMessage message={done} />
        <p className="m-0 text-ink-muted">{t("findings.transition.none")}</p>
      </div>
    );
  }

  const needsNote = noteRequired(to);
  const serverError =
    mutation.error && !(mutation.error instanceof ApiError && mutation.error.code === "reauth_required")
      ? mutation.error.message
      : null;

  return (
    <>
      <form ref={formRef} onSubmit={submit} noValidate className="flex flex-col gap-4">
        <StatusMessage message={done} />
        <fieldset
          className="m-0 min-w-0 border-0 p-0"
          data-invalid={error === "chooseState" ? "true" : undefined}
          aria-describedby={error === "chooseState" ? choiceErrorId : undefined}
        >
          <legend className="mb-1 p-0 font-semibold">
            {t("findings.transition.legend")}
          </legend>
          <p className="m-0 mb-2 text-sm text-ink-muted">{t("findings.transition.hint")}</p>
          <div className="grid gap-2">
            {targets.map((s) => (
              <label key={s} className={radioLabel}>
                <input
                  type="radio"
                  name="to"
                  value={s}
                  checked={to === s}
                  onChange={() => {
                    setTo(s);
                    if (error === "chooseState") setError(null);
                  }}
                  className="size-4 shrink-0 focus-visible:outline-none"
                />
                <span className="flex min-w-0 flex-1 flex-wrap items-center justify-between gap-2">
                  <span className="min-w-0">{t(`findings.transition.to.${s}`)}</span>
                  <StatusBadge kind="finding" state={s} />
                </span>
              </label>
            ))}
          </div>
          {error === "chooseState" && (
            <div className="mt-2">
              <FieldError id={choiceErrorId} message={t("findings.transition.chooseState")} />
            </div>
          )}
        </fieldset>

        <NoteField
          label={needsNote ? t("findings.transition.noteRequired") : t("findings.transition.note")}
          hint={t("findings.transition.noteHint")}
          name="note"
          maxLength={2000}
          required={needsNote}
          value={note}
          onChange={(e) => {
            setNote(e.target.value);
            if (error === "noteMissing" && e.target.value.trim()) setError(null);
          }}
          error={error === "noteMissing" ? t("findings.transition.noteMissing") : null}
        />

        <FormError message={serverError} />

        <div>
          <Button type="submit" variant="primary" disabled={mutation.isPending}>
            {t("findings.transition.submit")}
          </Button>
        </div>
      </form>

      <ConfirmDialog
        open={pendingReauth !== null}
        onClose={() => setPendingReauth(null)}
        title={t("findings.transition.reauthTitle")}
        object={pendingReauth ? t(`findings.transition.to.${pendingReauth.to}`) : ""}
        impact={pendingReauth?.note ?? t("findings.transition.hint")}
        reversible
        destructive={false}
        confirmLabel={t("findings.transition.submit")}
        requireReauth
        requireCode={reauth.requireCode}
        onConfirm={async (input) => {
          const body = pendingReauth;
          if (!body) return;
          let data: FindingDetail | undefined;
          await reauth.confirm(input, async () => {
            data = await send(body);
          });
          mutation.reset();
          if (data) applied(data, body);
        }}
      />
    </>
  );
}
