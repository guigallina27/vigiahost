import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, KeyRound } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, sessionQuery, unwrap, type Schemas } from "../api/client";
import { Button } from "../components/Button";
import { Field, FormError } from "../components/Field";
import { AuthLayout } from "./AuthLayout";
import { QrCode } from "./QrCode";
import { useLogout } from "./useLogout";

/** Configuração obrigatória do segundo fator (TOTP) e entrega única dos códigos de recuperação. */
export function MfaSetupPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const logout = useLogout();
  // useQuery (e não um efeito) para o StrictMode não pedir dois segredos.
  const setup = useQuery({
    queryKey: ["mfa-setup"],
    queryFn: () => unwrap(api.POST("/api/v1/auth/mfa/setup")),
    staleTime: Infinity,
    gcTime: 0,
    retry: false,
  });
  const [done, setDone] = useState<Schemas["MfaEnabled"] | null>(null);
  const enable = useMutation({
    mutationFn: (code: string) => unwrap(api.POST("/api/v1/auth/mfa/enable", { body: { code } })),
    onSuccess: setDone,
  });

  if (done) {
    return (
      <AuthLayout title={t("auth.recoveryTitle")} subtitle={t("auth.recoverySubtitle")}>
        <RecoveryCodes codes={done.recovery_codes} />
        <Button variant="primary" onClick={() => qc.setQueryData(sessionQuery.queryKey, done.session)}>
          {t("auth.recoveryContinue")}
        </Button>
      </AuthLayout>
    );
  }

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    enable.mutate(String(new FormData(e.currentTarget).get("code") ?? "").trim());
  }

  return (
    <AuthLayout title={t("auth.mfaSetupTitle")} subtitle={t("auth.mfaSetupSubtitle")}>
      {setup.isPending && <p className="m-0 text-ink-muted">{t("states.loading")}</p>}
      <FormError message={setup.error?.message} />
      {setup.data && (
        <>
          <ol className="m-0 flex flex-col gap-2 ps-5">
            <li>{t("auth.mfaStepApp")}</li>
            <li>{t("auth.mfaStepScan")}</li>
            <li>{t("auth.mfaStepCode")}</li>
          </ol>
          <div className="flex justify-center">
            <QrCode matrix={setup.data.matrix} label={t("auth.mfaQrLabel")} />
          </div>
          <details>
            <summary className="cursor-pointer font-semibold">{t("auth.mfaManual")}</summary>
            <p className="m-0 mt-2 font-mono break-all">{setup.data.secret}</p>
          </details>
          <form onSubmit={submit} className="flex flex-col gap-4">
            <Field label={t("auth.mfaCode")} name="code" autoComplete="one-time-code" inputMode="numeric" required mono maxLength={8} />
            <FormError message={enable.error?.message} />
            <Button type="submit" variant="primary" disabled={enable.isPending}>
              <KeyRound aria-hidden="true" className="size-4" />
              {t("auth.mfaEnable")}
            </Button>
          </form>
        </>
      )}
      <Button variant="ghost" onClick={() => logout.mutate()}>
        {t("auth.backToLogin")}
      </Button>
    </AuthLayout>
  );
}

/** Códigos de recuperação mostrados uma única vez, com opção de baixar em texto. */
export function RecoveryCodes({ codes }: { codes: string[] }) {
  const { t } = useTranslation();
  return (
    <>
      <ol className="m-0 grid list-none grid-cols-2 gap-2 rounded-control bg-sunken p-4 font-mono text-base">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ol>
      <DownloadText text={codes.join("\n") + "\n"} filename="vigiahost-codigos-de-recuperacao.txt" label={t("auth.recoveryDownload")} />
    </>
  );
}

/** Botão que baixa um texto gerado na hora (o endereço blob: é criado no clique e liberado em seguida). */
export function DownloadText({ text, filename, label }: { text: string; filename: string; label: string }) {
  function download() {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }
  return (
    <Button onClick={download}>
      <Download aria-hidden="true" className="size-4" />
      {label}
    </Button>
  );
}
