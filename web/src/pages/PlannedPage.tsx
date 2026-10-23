import type { ParseKeys } from "i18next";
import { Construction } from "lucide-react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../layout/PageHeader";

/** Só em desenvolvimento: ocupa as rotas planejadas para validar a navegação completa. */
export function PlannedPage({ label, phase }: { label: ParseKeys; phase: string }) {
  const { t } = useTranslation();
  return (
    <>
      <PageHeader title={t(label)} subtitle={`${t("app.planned")} · ${phase}`} />
      <EmptyState icon={Construction} title={t("planned.title")} description={t("planned.description")} />
    </>
  );
}
