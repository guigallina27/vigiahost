import { Monitor, Moon, Sun, type LucideIcon } from "lucide-react";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { Panel } from "../components/Panel";
import { PageHeader } from "../layout/PageHeader";
import { useSchemePreference, useSystemScheme, type SchemePreference } from "../lib/theme";

export function SettingsPage() {
  const { t } = useTranslation();
  return (
    <>
      <PageHeader title={t("settings.title")} subtitle={t("settings.subtitle")} />
      <div className="max-w-2xl">
        <Panel title={t("settings.appearance")}>
          <ThemeChoice />
        </Panel>
      </div>
    </>
  );
}

/** Três estados explícitos numa tela de configuração (guia dark-mode-toggle): Sistema, Claro e Escuro. */
function ThemeChoice() {
  const { t } = useTranslation();
  const [pref, setPref] = useSchemePreference();
  const system = useSystemScheme();
  const hintId = useId();
  const options: { value: SchemePreference; label: string; icon: LucideIcon }[] = [
    {
      value: "system",
      label: t("theme.systemCurrent", { scheme: system === "dark" ? t("theme.darkLower") : t("theme.lightLower") }),
      icon: Monitor,
    },
    { value: "light", label: t("theme.light"), icon: Sun },
    { value: "dark", label: t("theme.dark"), icon: Moon },
  ];
  return (
    <fieldset className="m-0 min-w-0 border-0 p-0" aria-describedby={hintId}>
      <legend className="mb-1 p-0 text-base font-semibold">{t("theme.legend")}</legend>
      <p id={hintId} className="m-0 mb-3 text-sm text-ink-muted">
        {t("theme.hint")}
      </p>
      <div className="grid gap-2 sm:grid-cols-3">
        {options.map((o) => (
          <label
            key={o.value}
            className="flex min-h-11 cursor-pointer items-center gap-3 rounded-control border border-line-strong bg-surface px-3 py-2 has-checked:border-accent has-checked:bg-accent-soft has-focus-visible:outline-3 has-focus-visible:outline-offset-2 has-focus-visible:outline-(--vh-focus)"
          >
            <input
              type="radio"
              name="color-scheme"
              value={o.value}
              checked={pref === o.value}
              onChange={() => setPref(o.value)}
              className="size-4 shrink-0 focus-visible:outline-none"
            />
            <o.icon aria-hidden="true" className="size-4 shrink-0" />
            <span className="min-w-0">{o.label}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}
