import { lazy, Suspense } from "react";
import { createBrowserRouter, type RouteObject } from "react-router";
import { AppShell } from "./layout/AppShell";
import { plannedItems } from "./layout/navigation";
import { NotFoundPage } from "./pages/NotFoundPage";
import { OverviewPage } from "./pages/OverviewPage";
import { PlannedPage } from "./pages/PlannedPage";
import { SettingsPage } from "./pages/SettingsPage";

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
  {
    path: "/",
    element: <AppShell />,
    children: [
      { index: true, element: <OverviewPage /> },
      { path: "configuracoes", element: <SettingsPage /> },
      ...devRoutes,
      { path: "*", element: <NotFoundPage /> },
    ],
  },
];

export const router = createBrowserRouter(routes);
