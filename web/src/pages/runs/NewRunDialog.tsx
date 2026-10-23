import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play } from "lucide-react";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { api, unwrap } from "../../api/client";
import { Button } from "../../components/Button";
import { FormError, SelectField, TextAreaField } from "../../components/Field";
import { noAccounts, type AccountChoice } from "../accounts/accounts";
import { AccountPicker } from "../accounts/AccountPicker";
import { useProfileLabel, useProfileSummary } from "./RunBits";
import { resourcesQuery } from "./queries";
import { buildRunCreate, newIdempotencyKey, type DraftError, type RunCreate, type RunKind } from "./runFormat";

type Props = { open: boolean; onClose: () => void };

/**
 * Diálogo "Nova verificação" sobre o <dialog> nativo (showModal: foco preso, Esc e fundo inerte pelo navegador).
 * O formulário só existe enquanto o diálogo está aberto, então cada abertura começa limpa.
 */
export function NewRunDialog({ open, onClose }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const descId = useId();

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    else if (!open && dialog.open) dialog.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      aria-describedby={descId}
      onClose={onClose}
      className="vh-dialog m-auto max-h-[calc(100dvh-2rem)] w-[min(40rem,calc(100vw-2rem))] overflow-y-auto rounded-panel border border-line-strong bg-surface p-0 text-ink shadow-2xl"
    >
      {open && <NewRunForm titleId={titleId} descId={descId} onClose={onClose} />}
    </dialog>
  );
}

function draftErrorMessage(t: TFunction, e: DraftError): string {
  switch (e.code) {
    case "pathsRequired":
      return t("runs.new.errors.pathsRequired");
    case "accountsRequired":
      return t("runs.new.errors.accountsRequired");
    case "notAbsolute":
      return t("runs.new.errors.notAbsolute", { path: e.path });
    case "pathsTooMany":
      return t("runs.new.errors.pathsTooMany", { max: e.max });
    case "excludeTooMany":
      return t("runs.new.errors.excludeTooMany", { max: e.max });
  }
}

function NewRunForm({ titleId, descId, onClose }: { titleId: string; descId: string; onClose: () => void }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const profileLabel = useProfileLabel();
  const profileSummary = useProfileSummary();
  const resources = useQuery(resourcesQuery);

  const [kind, setKind] = useState<RunKind>("files");
  const [paths, setPaths] = useState("");
  const [accounts, setAccounts] = useState<AccountChoice>(noAccounts);
  const [exclude, setExclude] = useState("");
  const [incremental, setIncremental] = useState(true);
  const [profile, setProfile] = useState("");
  const [draftError, setDraftError] = useState<DraftError | null>(null);
  // Mesma chave enquanto o pedido não muda: clique duplo ou nova tentativa devolvem a mesma execução.
  const idempotencyKey = useRef(newIdempotencyKey());
  const changed = () => {
    idempotencyKey.current = newIdempotencyKey();
    setDraftError(null);
  };

  const profiles = resources.data?.profiles.map((p) => p.profile) ?? [];
  const defaultProfile = profiles.find((p) => p.name === "padrao")?.name ?? profiles[0]?.name ?? "";
  const selectedName = profile || defaultProfile;
  const selected = profiles.find((p) => p.name === selectedName);

  const create = useMutation({
    mutationFn: ({ body, key }: { body: RunCreate; key: string | undefined }) =>
      unwrap(api.POST("/api/v1/runs", { body, ...(key ? { params: { header: { "Idempotency-Key": key } } } : {}) })),
    onSuccess: (run) => {
      void qc.invalidateQueries({ queryKey: ["runs"] });
      void qc.invalidateQueries({ queryKey: ["overview"] });
      onClose();
      void navigate(`/execucoes/${encodeURIComponent(run.id)}`);
    },
  });

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const built = buildRunCreate({ kind, paths, exclude, incremental, profile: selected ? selectedName : "", accounts });
    if (!built.ok) {
      setDraftError(built.error);
      return;
    }
    create.mutate({ body: built.body, key: idempotencyKey.current });
  }

  const kinds: { value: RunKind; label: string; hint: string }[] = [
    { value: "files", label: t("runs.new.kindFiles"), hint: t("runs.new.kindFilesHint") },
    { value: "processes", label: t("runs.new.kindProcesses"), hint: t("runs.new.kindProcessesHint") },
    { value: "integrity", label: t("runs.new.kindIntegrity"), hint: t("runs.new.kindIntegrityHint") },
    { value: "updates", label: t("runs.new.kindUpdates"), hint: t("runs.new.kindUpdatesHint") },
  ];
  const pathsInvalid = draftError?.field === "paths";
  const excludeInvalid = draftError?.field === "exclude";
  const accountsError = draftError?.field === "accounts" ? draftErrorMessage(t, draftError) : null;
  const message = draftError && !accountsError ? draftErrorMessage(t, draftError) : create.error?.message;
  const withAccounts = accounts.mode !== "none";

  return (
    <form onSubmit={submit} noValidate className="flex flex-col gap-5 p-5">
      <div className="flex flex-col gap-1">
        <h2 id={titleId} className="m-0 text-xl leading-tight font-bold">
          {t("runs.new.title")}
        </h2>
        <p id={descId} className="m-0 text-ink-muted">
          {t("runs.new.description")}
        </p>
      </div>

      <fieldset className="m-0 flex min-w-0 flex-col gap-2 border-0 p-0">
        <legend className="mb-2 p-0 font-semibold">{t("runs.new.kindLegend")}</legend>
        <div className="grid gap-2 sm:grid-cols-2">
          {kinds.map((k) => (
            <label
              key={k.value}
              className="grid min-h-11 min-w-0 cursor-pointer grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3 rounded-control border border-line-strong bg-bg p-3 has-checked:border-accent has-checked:bg-accent-soft"
            >
              <input
                type="radio"
                name="kind"
                value={k.value}
                checked={kind === k.value}
                onChange={() => {
                  setKind(k.value);
                  changed();
                }}
                className="row-span-2 mt-1 size-4 shrink-0 accent-(--vh-accent)"
              />
              <span className="font-semibold">{k.label}</span>
              <span className="text-sm text-ink-muted">{k.hint}</span>
            </label>
          ))}
        </div>
      </fieldset>

      {kind === "files" && (
        <>
          <TextAreaField
            label={t("runs.new.paths")}
            hint={withAccounts ? t("runs.new.pathsOptionalHint") : t("runs.new.pathsHint")}
            name="paths"
            mono
            rows={4}
            required={!withAccounts}
            spellCheck={false}
            autoCapitalize="none"
            autoComplete="off"
            value={paths}
            aria-invalid={pathsInvalid || undefined}
            onChange={(e) => {
              setPaths(e.target.value);
              changed();
            }}
          />
          <AccountPicker
            value={accounts}
            onChange={(next) => {
              setAccounts(next);
              changed();
            }}
            error={accountsError}
          />
          <TextAreaField
            label={t("runs.new.exclude")}
            hint={t("runs.new.excludeHint")}
            name="exclude"
            mono
            rows={3}
            spellCheck={false}
            autoCapitalize="none"
            autoComplete="off"
            value={exclude}
            aria-invalid={excludeInvalid || undefined}
            onChange={(e) => {
              setExclude(e.target.value);
              changed();
            }}
          />
          <label className="grid min-h-11 cursor-pointer grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3">
            <input
              type="checkbox"
              name="incremental"
              checked={incremental}
              onChange={(e) => {
                setIncremental(e.target.checked);
                changed();
              }}
              className="row-span-2 mt-1 size-4 shrink-0 accent-(--vh-accent)"
            />
            <span className="font-semibold">{t("runs.new.incremental")}</span>
            <span className="text-sm text-ink-muted">{t("runs.new.incrementalHint")}</span>
          </label>
        </>
      )}

      {resources.isPending ? (
        <p className="m-0 text-sm text-ink-muted">{t("runs.new.profilesLoading")}</p>
      ) : resources.isError || profiles.length === 0 ? (
        <p className="m-0 rounded-control bg-(--vh-medium-bg) p-3 text-sm text-(--vh-medium-fg)">
          {t("runs.new.profilesError", { cause: resources.error?.message ?? "—" })}
        </p>
      ) : (
        <SelectField
          label={t("runs.new.profile")}
          hint={
            <>
              {t("runs.new.profileHint")}
              {selected && <span className="block">{profileSummary(selected)}</span>}
            </>
          }
          name="profile"
          value={selectedName}
          onChange={(e) => {
            setProfile(e.target.value);
            changed();
          }}
          options={profiles.map((p) => ({ value: p.name, label: profileLabel(p.name) }))}
        />
      )}

      <FormError message={message} />

      <div className="flex flex-wrap justify-end gap-2">
        <Button type="button" variant="secondary" onClick={onClose}>
          {t("dialog.cancel")}
        </Button>
        <Button type="submit" variant="primary" disabled={create.isPending}>
          <Play aria-hidden="true" className="size-4" />
          {create.isPending ? t("runs.new.submitting") : t("runs.new.submit")}
        </Button>
      </div>
    </form>
  );
}
