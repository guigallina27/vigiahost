import { Menu, X } from "lucide-react";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { NavLink, Outlet, useLocation } from "react-router";
import { visibleNavigation } from "./navigation";

function Brand() {
  return (
    <span className="flex items-center gap-2.5">
      <svg aria-hidden="true" viewBox="0 0 32 32" className="size-8 shrink-0">
        <rect width="32" height="32" rx="7" fill="oklch(33% 0.04 175)" />
        <path d="M7 9l9 16 9-16" fill="none" stroke="oklch(95% 0.01 150)" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="16" cy="9.5" r="2.6" fill="var(--vh-signal)" />
      </svg>
      <span className="text-lg font-bold tracking-tight">VigiaHost</span>
    </span>
  );
}

export function AppShell() {
  const { t } = useTranslation();
  const { pathname } = useLocation();
  // O menu móvel guarda a rota em que foi aberto: ao navegar, fecha sozinho.
  const [openAt, setOpenAt] = useState<string | null>(null);
  const menuOpen = openAt === pathname;
  const navId = useId();
  const groups = visibleNavigation(import.meta.env.DEV);

  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[16rem_minmax(0,1fr)]">
      <a
        href="#conteudo"
        className="visually-hidden z-50 rounded-control bg-surface px-4 py-2 font-semibold text-ink shadow-lg focus:fixed focus:top-3 focus:left-3"
      >
        {t("app.skipToContent")}
      </a>

      <div className="bg-nav text-nav-ink lg:sticky lg:top-0 lg:h-dvh lg:overflow-y-auto [&_:focus-visible]:outline-(--vh-nav-focus)">
        <div className="flex items-center justify-between gap-2 px-4 py-3 lg:py-5">
          <Brand />
          <button
            type="button"
            className="inline-grid size-11 cursor-pointer place-items-center rounded-control border border-nav-muted lg:hidden"
            aria-expanded={menuOpen}
            aria-controls={navId}
            onClick={() => setOpenAt(menuOpen ? null : pathname)}
          >
            {menuOpen ? <X aria-hidden="true" className="size-5" /> : <Menu aria-hidden="true" className="size-5" />}
            <span className="visually-hidden">{menuOpen ? t("app.closeMenu") : t("app.openMenu")}</span>
          </button>
        </div>

        <nav id={navId} aria-label={t("app.mainNav")} className={`${menuOpen ? "block" : "hidden"} px-3 pb-6 lg:block`}>
          <ul className="m-0 flex list-none flex-col gap-5 p-0">
            {groups.map((group) => (
              <li key={group.id}>
                <span id={`${navId}-${group.id}`} className="vh-label block px-3 pb-1.5 text-nav-muted">
                  {t(group.label)}
                </span>
                <ul aria-labelledby={`${navId}-${group.id}`} className="m-0 flex list-none flex-col gap-0.5 p-0">
                  {group.items.map((item) => (
                    <li key={item.to}>
                      <NavLink
                        to={item.to}
                        end={item.to === "/"}
                        className={({ isActive }) =>
                          `group relative flex min-h-10 items-center gap-3 rounded-control px-3 py-1.5 no-underline ${
                            isActive
                              ? "bg-nav-active font-semibold text-nav-ink before:absolute before:inset-y-1.5 before:left-0 before:w-[3px] before:rounded-full before:bg-signal"
                              : "text-nav-ink/85 hover:bg-nav-active/60 hover:text-nav-ink"
                          }`
                        }
                      >
                        <item.icon aria-hidden="true" className="size-4.5 shrink-0" />
                        <span className="min-w-0 flex-1">{t(item.label)}</span>
                        {item.phase && (
                          <span className="shrink-0 rounded-sm border border-nav-muted/60 px-1 font-mono text-[0.6875rem] text-nav-muted">
                            <span className="visually-hidden">{t("app.planned")}, </span>
                            {item.phase}
                          </span>
                        )}
                      </NavLink>
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </nav>
      </div>

      <main id="conteudo" tabIndex={-1} className="min-w-0 px-4 pb-12 focus:outline-none sm:px-8">
        <Outlet />
      </main>
    </div>
  );
}
