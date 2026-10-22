import { lazy, Suspense, type ComponentType } from "react";
import { createBrowserRouter, type RouteObject } from "react-router";
import { AuthGate } from "./auth/AuthGate";
import { RecoverPage } from "./auth/RecoverPage";
import { plannedItems } from "./layout/navigation";
import { NotFoundPage } from "./pages/NotFoundPage";
import { OverviewPage } from "./pages/OverviewPage";
import { PlannedPage } from "./pages/PlannedPage";
import { SettingsPage } from "./pages/SettingsPage";

// Páginas carregadas sob demanda: a visão geral e o acesso ficam no pacote inicial, o resto vem ao navegar.
function page(load: () => Promise<ComponentType>): RouteObject["element"] {
  const Page = lazy(async () => ({ default: await load() }));
  return (
    <Suspense>
      <Page />
    </Suspense>
  );
}

const pages: RouteObject[] = [
  { path: "achados", element: page(() => import("./pages/findings/FindingsPage").then((m) => m.FindingsPage)) },
  { path: "achados/:findingId", element: page(() => import("./pages/findings/FindingDetailPage").then((m) => m.FindingDetailPage)) },
  { path: "contas", element: page(() => import("./pages/accounts/AccountsPage").then((m) => m.AccountsPage)) },
  { path: "contas/:uid", element: page(() => import("./pages/accounts/AccountDetailPage").then((m) => m.AccountDetailPage)) },
  { path: "excecoes", element: page(() => import("./pages/findings/ExceptionsPage").then((m) => m.ExceptionsPage)) },
  { path: "execucoes", element: page(() => import("./pages/runs/RunsPage").then((m) => m.RunsPage)) },
  { path: "execucoes/:runId", element: page(() => import("./pages/runs/RunDetailPage").then((m) => m.RunDetailPage)) },
  { path: "cobertura", element: page(() => import("./pages/CoveragePage").then((m) => m.CoveragePage)) },
  { path: "processos", element: page(() => import("./pages/inventory/ProcessesPage").then((m) => m.ProcessesPage)) },
  { path: "agendamentos", element: page(() => import("./pages/config/SchedulesPage").then((m) => m.SchedulesPage)) },
  { path: "recursos", element: page(() => import("./pages/config/ResourcesPage").then((m) => m.ResourcesPage)) },
  { path: "motores", element: page(() => import("./pages/config/EnginesPage").then((m) => m.EnginesPage)) },
  { path: "regras", element: page(() => import("./pages/config/RulesPage").then((m) => m.RulesPage)) },
  { path: "usuarios", element: page(() => import("./pages/admin/UsersPage").then((m) => m.UsersPage)) },
  { path: "tokens", element: page(() => import("./pages/admin/TokensPage").then((m) => m.TokensPage)) },
  { path: "auditoria", element: page(() => import("./pages/admin/AuditPage").then((m) => m.AuditPage)) },
  { path: "backup", element: page(() => import("./pages/admin/BackupPage").then((m) => m.BackupPage)) },
];

// O catálogo só existe no servidor de desenvolvimento; o import condicional some do build de produção.
const CatalogPage = import.meta.env.DEV ? lazy(() => import("./pages/CatalogPage")) : null;

const devRoutes: RouteObject[] = import.meta.env.DEV
  ? [
      ...(CatalogPage ? [{ path: "catalogo", element: <Suspense><CatalogPage /></Suspense> }] : []),
      ...plannedItems.map((item) => ({
        path: item.to.slice(1),
        element: <PlannedPage label={item.label} phase={item.phase ?? ""} />,
      })),
    ]
  : [];

export const routes: RouteObject[] = [
  // Recuperação de senha fica fora do portão: quem a usa não tem sessão.
  { path: "/recuperar", element: <RecoverPage /> },
  {
    path: "/",
    element: <AuthGate />,
    children: [
      { index: true, element: <OverviewPage /> },
      { path: "configuracoes", element: <SettingsPage /> },
      ...pages,
      ...devRoutes,
      { path: "*", element: <NotFoundPage /> },
    ],
  },
];

export const router = createBrowserRouter(routes);
