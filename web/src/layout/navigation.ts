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
      { to: "/achados", label: "nav.findings", icon: ScanSearch, phase: "1A" },
      { to: "/contas", label: "nav.accounts", icon: Users, phase: "1B" },
      { to: "/execucoes", label: "nav.runs", icon: ListChecks, phase: "1A" },
      { to: "/cobertura", label: "nav.coverage", icon: PieChart, phase: "1A" },
    ],
  },
  {
    id: "investigate",
    label: "nav.groups.investigate",
    items: [
      { to: "/processos", label: "nav.processes", icon: Cpu, phase: "1A" },
      { to: "/integridade", label: "nav.integrity", icon: FileCheck, phase: "2" },
      { to: "/evidencias", label: "nav.evidence", icon: Archive, phase: "2" },
    ],
  },
  {
    id: "respond",
    label: "nav.groups.respond",
    items: [
      { to: "/quarentena", label: "nav.quarantine", icon: Lock, phase: "2" },
      { to: "/excecoes", label: "nav.exceptions", icon: ShieldCheck, phase: "1B" },
    ],
  },
  {
    id: "configure",
    label: "nav.groups.configure",
    items: [
      { to: "/agendamentos", label: "nav.schedules", icon: CalendarClock, phase: "1A" },
      { to: "/recursos", label: "nav.resources", icon: Gauge, phase: "1A" },
      { to: "/motores", label: "nav.engines", icon: SlidersHorizontal, phase: "1A" },
      { to: "/regras", label: "nav.rules", icon: BookOpen, phase: "1A" },
      { to: "/notificacoes", label: "nav.notifications", icon: Bell, phase: "1B" },
    ],
  },
  {
    id: "administer",
    label: "nav.groups.administer",
    items: [
      { to: "/usuarios", label: "nav.users", icon: UserCog, phase: "1A" },
      { to: "/auditoria", label: "nav.audit", icon: ClipboardList, phase: "1A" },
      { to: "/backup", label: "nav.backup", icon: DatabaseBackup, phase: "1B" },
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
