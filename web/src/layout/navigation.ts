import {
  Archive,
  Bell,
  BookOpen,
  CalendarClock,
  ClipboardList,
  Cpu,
  DatabaseBackup,
  FileCheck,
  Gauge,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  Lock,
  Palette,
  PieChart,
  ScanSearch,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  UserCog,
  Users,
  type LucideIcon,
} from "lucide-react";
import type { ParseKeys } from "i18next";

export type NavItem = {
  to: string;
  label: ParseKeys;
  icon: LucideIcon;
  /** Fase do plano em que a página entra; páginas ainda não feitas só aparecem em desenvolvimento. */
  phase?: string;
};

export type NavGroup = { id: string; label: ParseKeys; items: NavItem[] };

// Navegação agrupada pela tarefa do operador (escopo, seção 14.1).
export const navigation: NavGroup[] = [
  {
    id: "monitor",
    label: "nav.groups.monitor",
    items: [
      { to: "/", label: "nav.overview", icon: LayoutDashboard },
      { to: "/achados", label: "nav.findings", icon: ScanSearch },
      { to: "/contas", label: "nav.accounts", icon: Users },
      { to: "/execucoes", label: "nav.runs", icon: ListChecks },
      { to: "/cobertura", label: "nav.coverage", icon: PieChart },
    ],
  },
  {
    id: "investigate",
    label: "nav.groups.investigate",
    items: [
      { to: "/processos", label: "nav.processes", icon: Cpu },
      { to: "/integridade", label: "nav.integrity", icon: FileCheck, phase: "2" },
      { to: "/evidencias", label: "nav.evidence", icon: Archive, phase: "2" },
    ],
  },
  {
    id: "respond",
    label: "nav.groups.respond",
    items: [
      { to: "/quarentena", label: "nav.quarantine", icon: Lock, phase: "2" },
      { to: "/excecoes", label: "nav.exceptions", icon: ShieldCheck },
    ],
  },
  {
    id: "configure",
    label: "nav.groups.configure",
    items: [
      { to: "/agendamentos", label: "nav.schedules", icon: CalendarClock },
      { to: "/recursos", label: "nav.resources", icon: Gauge },
      { to: "/motores", label: "nav.engines", icon: SlidersHorizontal },
      { to: "/regras", label: "nav.rules", icon: BookOpen, phase: "1A" },
      { to: "/notificacoes", label: "nav.notifications", icon: Bell },
    ],
  },
  {
    id: "administer",
    label: "nav.groups.administer",
    items: [
      { to: "/usuarios", label: "nav.users", icon: UserCog },
      { to: "/tokens", label: "nav.tokens", icon: KeyRound },
      { to: "/auditoria", label: "nav.audit", icon: ClipboardList },
      { to: "/backup", label: "nav.backup", icon: DatabaseBackup },
      { to: "/configuracoes", label: "nav.settings", icon: Settings },
    ],
  },
];

export const devNavigation: NavGroup = {
  id: "development",
  label: "nav.groups.development",
  items: [{ to: "/catalogo", label: "nav.catalog", icon: Palette }],
};

/** Grupos visíveis: em produção, só páginas prontas; em desenvolvimento, também as planejadas e o catálogo. */
export function visibleNavigation(dev: boolean): NavGroup[] {
  if (dev) return [...navigation, devNavigation];
  return navigation
    .map((g) => ({ ...g, items: g.items.filter((i) => !i.phase) }))
    .filter((g) => g.items.length > 0);
}

export const plannedItems = navigation.flatMap((g) => g.items.filter((i) => i.phase));
