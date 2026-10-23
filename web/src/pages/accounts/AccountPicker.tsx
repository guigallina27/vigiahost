import { useQuery } from "@tanstack/react-query";
import { useDeferredValue, useId, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Field } from "../../components/Field";
import { PathText } from "../../components/PathText";
import { formatNumber } from "../../lib/format";
import { SafeText } from "../inventory/SafeText";
import { isExecutorUnavailable, matchesAccount, sortAccounts, toggleUid, type AccountChoice } from "./accounts";
import { accountsQuery } from "./queries";

/** Quantas contas a lista de escolha mostra por vez; a busca refina o resto. */
const SHOWN = 50;

type Props = {
  value: AccountChoice;
  onChange: (next: AccountChoice) => void;
  /** Mensagem de validação (ex.: "Escolha ao menos uma conta"). */
  error?: string | null;
};

/**
 * Escolha de "Contas do servidor" nos formulários de verificação e de agendamento: nenhuma, todas as contas de
 * hospedagem (resolvidas a cada execução) ou contas escolhidas da lista.
 */
export function AccountPicker({ value, onChange, error }: Props) {
  const { t } = useTranslation();
  const name = useId();
  const hintId = useId();
  const errorId = useId();
  const modes: { mode: AccountChoice["mode"]; label: string; hint: string }[] = [
    { mode: "none", label: t("accounts.picker.none"), hint: t("accounts.picker.noneHint") },
    { mode: "all", label: t("accounts.picker.all"), hint: t("accounts.picker.allHint") },
    { mode: "selected", label: t("accounts.picker.selected"), hint: t("accounts.picker.selectedHint") },
  ];
  return (
    <fieldset
      className="m-0 flex min-w-0 flex-col gap-2 border-0 p-0"
      aria-describedby={[hintId, error ? errorId : ""].filter(Boolean).join(" ")}
    >
      <legend className="mb-1 p-0 font-semibold">{t("accounts.picker.legend")}</legend>
      <p id={hintId} className="m-0 text-sm text-ink-muted">
        {t("accounts.picker.hint")}
      </p>
      <div className="grid gap-2 sm:grid-cols-3">
        {modes.map((m) => (
          <label
            key={m.mode}
            className="grid min-h-11 min-w-0 cursor-pointer grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3 rounded-control border border-line-strong bg-bg p-3 has-checked:border-accent has-checked:bg-accent-soft"
          >
            <input
              type="radio"
              name={name}
              value={m.mode}
              checked={value.mode === m.mode}
              onChange={() => onChange({ ...value, mode: m.mode })}
              className="row-span-2 mt-1 size-4 shrink-0 accent-(--vh-accent)"
            />
            <span className="font-semibold">{m.label}</span>
            <span className="text-sm text-ink-muted">{m.hint}</span>
          </label>
        ))}
      </div>
      {value.mode === "selected" && <AccountList value={value} onChange={onChange} />}
      {error && (
        <span id={errorId} role="alert" className="text-sm text-(--vh-critical-fg)">
          {error}
        </span>
      )}
    </fieldset>
  );
}

function AccountList({ value, onChange }: { value: AccountChoice; onChange: (next: AccountChoice) => void }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const accounts = useQuery(accountsQuery(false));
  const [text, setText] = useState("");
  const q = useDeferredValue(text);
  const matches = useMemo(
    () => sortAccounts((accounts.data?.accounts ?? []).filter((a) => matchesAccount(a, q)), "name"),
    [accounts.data, q],
  );

  if (accounts.isPending) {
    return (
      <p role="status" className="m-0 text-sm text-ink-muted">
        {t("states.loading")}
      </p>
    );
  }
  if (accounts.isError) {
    return (
      <p role="alert" className="m-0 rounded-control bg-(--vh-medium-bg) p-3 text-sm text-(--vh-medium-fg)">
        {isExecutorUnavailable(accounts.error)
          ? t("accounts.picker.executorDown")
          : t("accounts.picker.loadError", { cause: accounts.error.message })}
      </p>
    );
  }
  if (accounts.data.accounts.length === 0) {
    return <p className="m-0 text-sm text-ink-muted">{t("accounts.picker.empty")}</p>;
  }

  const chosen = new Set(value.uids);
  const shown = matches.slice(0, SHOWN);
  return (
    <div className="flex min-w-0 flex-col gap-2 rounded-control border border-line bg-sunken p-3">
      <Field
        type="search"
        label={t("accounts.picker.search")}
        value={text}
        maxLength={256}
        onChange={(e) => setText(e.target.value)}
        autoComplete="off"
        spellCheck={false}
      />
      <p role="status" className="m-0 text-sm text-ink-muted">
        {t("accounts.picker.selectedCount", { count: value.uids.length, formatted: formatNumber(value.uids.length, lng) })}
        {matches.length > SHOWN && ` ${t("accounts.picker.refine", { shown: SHOWN, total: formatNumber(matches.length, lng) })}`}
      </p>
      {shown.length === 0 ? (
        <p className="m-0 text-sm text-ink-muted">{t("accounts.picker.noMatch")}</p>
      ) : (
        <ul className="m-0 flex max-h-64 list-none flex-col gap-1 overflow-y-auto p-0">
          {shown.map((a) => (
            <li key={a.uid} className="min-w-0">
              <label className="flex min-h-11 min-w-0 cursor-pointer items-center gap-3 rounded-control px-2 hover:bg-surface">
                <input
                  type="checkbox"
                  className="size-5 shrink-0 accent-(--vh-accent)"
                  checked={chosen.has(a.uid)}
                  onChange={() => onChange({ ...value, uids: toggleUid(value.uids, a.uid) })}
                />
                <span className="min-w-0 [overflow-wrap:anywhere]">
                  <span className="font-semibold">
                    <SafeText text={a.name} />
                  </span>{" "}
                  <span className="text-sm text-ink-muted">
                    ({a.uid}) · <PathText path={a.home} />
                  </span>
                </span>
              </label>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
