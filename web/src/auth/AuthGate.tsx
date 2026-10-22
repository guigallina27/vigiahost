import { useQuery } from "@tanstack/react-query";
import { PlugZap } from "lucide-react";
import { useTranslation } from "react-i18next";
import { sessionQuery } from "../api/client";
import { Button } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { AppShell } from "../layout/AppShell";
import { AuthLayout } from "./AuthLayout";
import { LoginPage } from "./LoginPage";
import { MfaSetupPage } from "./MfaSetupPage";
import { MfaVerifyPage } from "./MfaVerifyPage";
import { SetupPage } from "./SetupPage";

/** Decide pela sessão o que mostrar: primeiro acesso, login, segundo fator ou o painel. */
export function AuthGate() {
  const { t } = useTranslation();
  const session = useQuery(sessionQuery);

  if (session.isPending) {
    return (
      <AuthLayout title={t("auth.loadingTitle")}>
        <p className="m-0 text-ink-muted">{t("states.loading")}</p>
      </AuthLayout>
    );
  }
  if (session.isError) {
    return (
      <AuthLayout title={t("auth.unreachableTitle")}>
        <EmptyState
          tone="error"
          icon={PlugZap}
          headingLevel={2}
          title={t("overview.unreachableTitle")}
          description={session.error.message}
          action={
            <Button variant="primary" onClick={() => void session.refetch()}>
              {t("auth.retry")}
            </Button>
          }
        />
      </AuthLayout>
    );
  }
  const s = session.data;
  if (s.setup_required) return <SetupPage session={s} />;
  if (!s.authenticated) {
    if (s.stage === "password") return <MfaVerifyPage />;
    if (s.stage === "mfa_setup") return <MfaSetupPage />;
    return <LoginPage session={s} />;
  }
  return <AppShell />;
}
