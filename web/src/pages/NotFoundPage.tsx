import { MapPinOff } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Link, useLocation } from "react-router";
import { EmptyState } from "../components/EmptyState";
import { PathText } from "../components/PathText";
import { PageHeader } from "../layout/PageHeader";

export function NotFoundPage() {
  const { t } = useTranslation();
  const { pathname } = useLocation();
  return (
    <>
      <PageHeader title={t("notFound.title")} />
      <EmptyState
        icon={MapPinOff}
        title={t("notFound.description")}
        description={<PathText path={pathname} />}
        action={
          <Link to="/" className="font-semibold text-accent underline underline-offset-4">
            {t("notFound.back")}
          </Link>
        }
      />
    </>
  );
}
