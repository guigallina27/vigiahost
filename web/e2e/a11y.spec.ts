import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type Route } from "@playwright/test";
import type { components } from "../src/api/schema";

// WCAG 2.1 AA (escopo, seção 14.3) com axe-core, nos dois temas, mais checagens de teclado, reflow e tema.
// A API é simulada aqui com respostas tipadas pelo contrato (api/openapi.yaml → src/api/schema.d.ts): se o contrato
// mudar, o typecheck acusa os dados de teste desatualizados.

type S = components["schemas"];

// Datas fixas: o relógio do navegador é congelado em NOW e todos os dados são anteriores a ele.
const NOW = "2026-10-22T12:00:00Z";
const SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const FILES_RUN = "r-20261021-files";
const PROC_RUN = "r-20261021-proc";

// --- Sessão ---

const admin: S["CurrentUser"] = {
  id: 1,
  username: "admin",
  display_name: "Ana Administradora",
  role: "admin",
  mfa_enabled: true,
  mfa_required: true,
  recovery_codes_left: 8,
};

const sessions = {
  // Sessão completa de administrador com segundo fator ativo: o AuthGate mostra o AppShell.
  admin: {
    authenticated: true,
    setup_required: false,
    secure_transport: true,
    stage: "full",
    user: admin,
    idle_timeout_seconds: 1800,
  },
  anonymous: { authenticated: false, setup_required: false, secure_transport: true },
  insecure: { authenticated: false, setup_required: false, secure_transport: false },
  password: { authenticated: false, setup_required: false, secure_transport: true, stage: "password", user: admin },
} satisfies Record<string, S["Session"]>;

type SessionKind = keyof typeof sessions;

// Desafio ALTCHA v2 plausível; com auto="off" o widget só o pede ao marcar a caixa, mas fica simulado mesmo assim.
const challenge: S["AuthChallenge"] = {
  parameters: {
    algorithm: "PBKDF2/SHA-256",
    nonce: "6f1c2a9e0b7d4c3a",
    salt: "c0ffee00c0ffee00",
    cost: 1000,
    keyLength: 32,
    keyPrefix: "00",
    expiresAt: 1792670400,
  },
  signature: "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
};

// --- Saúde ---

const system: S["SystemCapabilities"] = {
  distro_id: "almalinux",
  distro_version: "9.8",
  distro_name: "AlmaLinux 9.8 (Olive Jaguar)",
  distro_like: ["rhel", "centos", "fedora"],
  kernel: "5.14.0-611.el9.x86_64",
  arch: "amd64",
  systemd: true,
  cgroup_v2: true,
  psi: false,
};

const executorUp: S["ExecutorStatus"] = { connected: true, version: "0.1.0", protocol: "1.0", system };
const executorDown: S["ExecutorStatus"] = {
  connected: false,
  error: "dial unix /run/vigiahost-executor/executor.sock: connect: no such file or directory",
};

const healthy: S["Health"] = { status: "ok", version: "0.1.0", executor: executorUp };
const degraded: S["Health"] = { status: "degraded", version: "0.1.0", executor: executorDown };

// --- Execuções ---

const profile: S["ResourceProfile"] = {
  name: "padrao",
  cpu_quota_percent: 100,
  memory_max_bytes: 1_073_741_824,
  io_read_bytes_per_sec: 52_428_800,
  io_weight: 100,
  workers: 2,
  clamd_concurrency: 2,
  max_runtime_sec: 14_400,
  nice: 10,
  max_file_bytes: 33_554_432,
};

const skipped = { excluded: 120, too_large: 4, permission: 2, cached: 900 };

const filesRun: S["Run"] = {
  id: FILES_RUN,
  kind: "files",
  status: "completed",
  origin: "schedule",
  requested_by: "agendamento",
  schedule_id: 1,
  scheduled_for: "2026-10-21T03:00:00Z",
  paths: ["/home", "/var/www"],
  exclude: ["/home/*/cache"],
  incremental: true,
  profile,
  priority: 0,
  attempts: 1,
  created_at: "2026-10-21T03:00:00Z",
  started_at: "2026-10-21T03:00:05Z",
  finished_at: "2026-10-21T03:42:10Z",
  phase: "done",
  paused: false,
  files_seen: 15_234,
  files_eligible: 14_108,
  files_processed: 14_108,
  bytes_eligible: 2_147_483_648,
  bytes_processed: 2_147_483_648,
  findings_count: 2,
  error: "",
  summary: {
    status: "completed",
    started_at: "2026-10-21T03:00:05Z",
    finished_at: "2026-10-21T03:42:10Z",
    files_seen: 15_234,
    files_eligible: 14_108,
    bytes_eligible: 2_147_483_648,
    skipped,
    findings: 2,
    objects: 14_108,
    cache_hits: 900,
    files_per_second: 5.6,
    mb_per_second: 0.85,
    warnings: ["3 arquivos mudaram durante a leitura e serão verificados de novo."],
  },
};

const processesRun: S["Run"] = {
  ...filesRun,
  id: PROC_RUN,
  kind: "processes",
  origin: "manual",
  requested_by: "admin",
  scheduled_for: "2026-10-21T09:00:00Z",
  paths: [],
  exclude: [],
  incremental: false,
  created_at: "2026-10-21T09:00:00Z",
  started_at: "2026-10-21T09:00:02Z",
  finished_at: "2026-10-21T09:00:20Z",
  files_seen: 0,
  files_eligible: 0,
  files_processed: 0,
  bytes_eligible: 0,
  bytes_processed: 0,
  findings_count: 1,
  summary: {
    status: "completed",
    started_at: "2026-10-21T09:00:02Z",
    finished_at: "2026-10-21T09:00:20Z",
    files_seen: 0,
    files_eligible: 0,
    bytes_eligible: 0,
    findings: 1,
    objects: 212,
    cache_hits: 0,
    files_per_second: 0,
    mb_per_second: 0,
  },
};

const coverage: S["EngineCoverage"][] = [
  {
    engine: "yara-x",
    version: "1.9.0",
    rules_version: "2026.10.01",
    available: true,
    selftest_passed: true,
    selftest_detail: "EICAR detectado",
    eligible: 14_108,
    analyzed: 13_208,
    from_cache: 900,
    bytes_analyzed: 2_000_000_000,
    seconds: 2410,
    skipped: { too_large: 4 },
    errors: {},
    error: "",
  },
  {
    engine: "clamav",
    version: "1.4.3",
    rules_version: "27794",
    available: true,
    selftest_passed: true,
    selftest_detail: "EICAR detectado",
    eligible: 14_108,
    analyzed: 13_206,
    from_cache: 900,
    bytes_analyzed: 2_000_000_000,
    seconds: 2380,
    skipped: { too_large: 4, permission: 2 },
    errors: { timeout: 1 },
    error: "",
  },
];

const runDetails: Record<string, S["RunDetail"]> = {
  [FILES_RUN]: { run: filesRun, engines: coverage },
  [PROC_RUN]: { run: processesRun, engines: [] },
};

// --- Achados ---

const location: S["Location"] = {
  path: "/home/loja/public_html/uploads/x.php",
  dev: 64769,
  ino: 1_048_602,
  size: 10_240,
  mode: 0o100644,
  uid: 1001,
  gid: 1001,
  nlink: 1,
  mtime: "2026-10-19T22:14:00Z",
  ctime: "2026-10-19T22:14:00Z",
};

const criticalFinding: S["Finding"] = {
  id: 42,
  kind: "file",
  engine: "yara-x",
  engine_version: "1.9.0",
  rules_version: "2026.10.01",
  signature: "PHP_Webshell_Generic",
  source: "regras-base",
  license: "GPL-3.0",
  author: "Equipe VigiaHost",
  reference: "https://example.org/regras/php-webshell",
  description: "Webshell PHP genérico com execução de comandos",
  category: "webshell",
  severity: "critical",
  sha256: SHA,
  file_type: "php",
  state: "new",
  assignee: "",
  first_run: FILES_RUN,
  last_run: FILES_RUN,
  first_seen: "2026-10-20T03:30:00Z",
  last_seen: "2026-10-21T03:30:00Z",
  state_changed: "2026-10-20T03:30:00Z",
  times_seen: 2,
  location,
  locations_count: 1,
  evidence: { match: "eval(base64_decode(" },
};

const processFinding: S["Finding"] = {
  ...criticalFinding,
  id: 43,
  kind: "process",
  signature: "Linux_Miner_XMRig",
  description: "Minerador de criptomoeda em execução",
  category: "miner",
  severity: "high",
  state: "in_review",
  assignee: "admin",
  sha256: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
  file_type: "elf",
  first_run: PROC_RUN,
  last_run: PROC_RUN,
  first_seen: "2026-10-21T09:00:10Z",
  last_seen: "2026-10-21T09:00:10Z",
  state_changed: "2026-10-21T10:00:00Z",
  times_seen: 1,
  evidence: {},
  process: {
    pid: 4242,
    ppid: 1,
    uid: 1001,
    comm: "kworkerd",
    exe: "/tmp/.x/kworkerd",
    cmdline: ["/tmp/.x/kworkerd", "-o", "pool.example.net:3333"],
    cgroup: "/user.slice/user-1001.slice",
    exe_sha256: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    connected: ["203.0.113.7:3333"],
  },
};

const findingDetail: S["FindingDetail"] = {
  finding: criticalFinding,
  locations: [location],
  events: [
    { at: "2026-10-20T03:30:00Z", actor: "sistema", action: "created", from: "", to: "new", note: "" },
    { at: "2026-10-21T03:30:00Z", actor: "sistema", action: "seen", from: "new", to: "new", note: "Visto de novo" },
  ],
  allowed_transitions: ["in_review", "confirmed", "false_positive"],
};

const exceptions: S["Exception"][] = [
  {
    id: 7,
    scope: "hash_rule",
    sha256: SHA,
    signature: "PHP_Shell_Upload",
    path_prefix: "/home/loja/public_html/vendor/",
    reason: "Biblioteca legítima do tema, revisada pelo suporte",
    created_by: "admin",
    created_at: "2026-10-15T14:00:00Z",
    expires_at: "2027-01-15T14:00:00Z",
    revoked_by: "",
    active: true,
  },
];

// --- Configuração ---

const schedules: S["Schedule"][] = [
  {
    id: 1,
    name: "Varredura noturna",
    kind: "files",
    cron: "0 3 * * *",
    timezone: "America/Sao_Paulo",
    paths: ["/home", "/var/www"],
    exclude: ["/home/*/cache"],
    incremental: true,
    profile: "padrao",
    missed_policy: "run_once",
    enabled: true,
    next_run_at: "2026-10-23T06:00:00Z",
    last_run_at: "2026-10-22T06:00:00Z",
    created_by: "admin",
    created_at: "2026-10-01T12:00:00Z",
    updated_at: "2026-10-01T12:00:00Z",
    upcoming: ["2026-10-23T06:00:00Z", "2026-10-24T06:00:00Z", "2026-10-25T06:00:00Z"],
  },
];

const resources: S["Resources"] = {
  hardware: {
    cpus: 8,
    memory_bytes: 17_179_869_184,
    rotational: false,
    allow_no_reserve: false,
    systemd_version: "252",
    freezer: true,
  },
  profiles: [
    { profile: { ...profile, name: "leve", cpu_quota_percent: 50, workers: 1, clamd_concurrency: 1 }, custom: false, preset: true },
    { profile, custom: false, preset: true },
    { profile: { ...profile, name: "noturno", cpu_quota_percent: 200, workers: 4 }, custom: true, preset: false },
  ],
};

const engines: S["EngineStatus"] = {
  engines: [
    {
      id: "yara-x",
      name: "YARA-X",
      state: "operational",
      version: "1.9.0",
      rules_version: "2026.10.01",
      last_selftest: { run_id: FILES_RUN, passed: true, detail: "EICAR detectado", at: "2026-10-21T03:00:06Z" },
    },
    {
      id: "clamav",
      name: "ClamAV",
      state: "degraded",
      version: "1.4.3",
      signatures_version: "27794",
      signatures_date: "2026-10-18",
      mode: "clamd",
      detail: "Assinaturas com mais de 3 dias",
      last_selftest: { run_id: FILES_RUN, passed: true, detail: "EICAR detectado", at: "2026-10-21T03:00:06Z" },
    },
  ],
};

const overview = (executor: S["ExecutorStatus"]): S["Overview"] => ({
  executor,
  open_findings: { critical: 1, high: 1, medium: 0, low: 0, info: 0, total: 2 },
  active_runs: [],
  last_files_run: filesRun,
  last_processes_run: processesRun,
  recent_findings: [criticalFinding, processFinding],
  engines: engines.engines,
  has_runs: true,
  has_schedules: true,
});

// --- Inventário ---

const processInventory: S["ProcessInventory"] = {
  run_id: PROC_RUN,
  taken_at: "2026-10-21T09:00:20Z",
  processes: [
    {
      pid: 812,
      ppid: 1,
      uid: 0,
      user: "root",
      comm: "sshd",
      cmdline: ["/usr/sbin/sshd", "-D"],
      exe: "/usr/sbin/sshd",
      exe_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      package: "openssh-server-8.7p1-38.el9",
      unit: "sshd.service",
      cgroup: "/system.slice/sshd.service",
      cpu_percent: 0.1,
      rss_bytes: 8_388_608,
      threads: 1,
      listening: ["0.0.0.0:22"],
    },
    {
      pid: 4242,
      ppid: 1,
      uid: 1001,
      user: "loja",
      comm: "kworkerd",
      cmdline: ["/tmp/.x/kworkerd", "-o", "pool.example.net:3333"],
      exe: "/tmp/.x/kworkerd",
      exe_deleted: true,
      package: "-",
      cgroup: "/user.slice/user-1001.slice",
      cpu_percent: 97.5,
      rss_bytes: 268_435_456,
      threads: 8,
      connected: ["203.0.113.7:3333"],
      flags: ["Linux_Miner_XMRig"],
    },
  ],
};

const persistenceInventory: S["PersistenceInventory"] = {
  run_id: PROC_RUN,
  taken_at: "2026-10-21T09:00:20Z",
  baseline: false,
  items: [
    {
      kind: "cron",
      path: "/var/spool/cron/loja",
      detail: "*/5 * * * * /tmp/.x/kworkerd",
      sha256: "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9",
      owner: "loja",
      package: "-",
      change: "added",
    },
    {
      kind: "systemd-unit",
      path: "/etc/systemd/system/sshd.service.d/override.conf",
      detail: "ExecStart=/usr/sbin/sshd -D",
      owner: "root",
      package: "-",
      change: "",
    },
  ],
  removed: [{ kind: "authorized-keys", path: "/home/loja/.ssh/authorized_keys", owner: "loja", change: "removed" }],
};

// --- Administração ---

const users: S["User"][] = [
  {
    id: 1,
    username: "admin",
    display_name: "Ana Administradora",
    role: "admin",
    disabled: false,
    mfa_enabled: true,
    created_at: "2026-09-30T12:00:00Z",
    last_login_at: "2026-10-22T11:30:00Z",
  },
  {
    id: 2,
    username: "suporte",
    display_name: "Equipe de suporte",
    role: "reader",
    disabled: true,
    mfa_enabled: false,
    created_at: "2026-10-02T12:00:00Z",
  },
];

const tokens: S["ApiToken"][] = [
  {
    id: 3,
    name: "Monitoramento Zabbix",
    username: "admin",
    role: "reader",
    prefix: "vh_3f9a",
    created_at: "2026-10-05T12:00:00Z",
    expires_at: "2027-01-03T12:00:00Z",
    last_used: "2026-10-22T11:55:00Z",
  },
];

const audit: S["AuditPage"] = {
  chain_ok: true,
  entries: [
    {
      id: 120,
      at: "2026-10-22T11:30:00Z",
      actor: "admin",
      action: "login",
      target: "admin",
      detail: "",
      ip: "198.51.100.20",
    },
    {
      id: 119,
      at: "2026-10-21T18:00:00Z",
      actor: "admin",
      action: "exception_created",
      target: "exception:7",
      detail: "hash_rule PHP_Shell_Upload",
      ip: "198.51.100.20",
    },
  ],
};

const backups: S["BackupList"] = {
  directory: "/var/lib/vigiahost/backups",
  keep_automatic: 7,
  backups: [
    {
      name: "vigiahost-20261022-030000.db",
      created_at: "2026-10-22T03:00:00Z",
      size: 4_718_592,
      sha256: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
      schema_version: 12,
      product: "0.1.0",
      origin: "automatic",
    },
  ],
};

// --- Simulação da API ---

type Mode = "ok" | "degraded" | "offline";
type Mock = { mode?: Mode; session?: SessionKind };

const fail = (route: Route, status: number, error: string) => route.fulfill({ status, json: { error } satisfies S["Error"] });

/** Responde a toda a API do painel; `offline` derruba só a saúde e a visão geral (o serviço sumiu depois do login). */
async function mockApi(page: Page, { mode = "ok", session = "admin" }: Mock = {}) {
  await page.clock.setFixedTime(NOW);
  await page.route("**/api/v1/**", (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api\/v1/, "");
    const method = route.request().method();
    const executor = mode === "ok" ? executorUp : executorDown;

    if (path === "/events") return route.fulfill({ status: 204 });
    if (path === "/auth/session") return route.fulfill({ json: sessions[session] });
    if (path === "/auth/challenge") return route.fulfill({ json: challenge });
    if (method !== "GET") return fail(route, 405, "Simulação somente leitura");
    if (session !== "admin") return fail(route, 401, "Sessão expirada");

    if (path === "/health") {
      if (mode === "offline") return route.abort("connectionrefused");
      return route.fulfill({ status: mode === "ok" ? 200 : 503, json: mode === "ok" ? healthy : degraded });
    }
    if (path === "/overview") {
      if (mode === "offline") return route.abort("connectionrefused");
      return route.fulfill({ json: overview(executor) });
    }
    if (path === "/runs") {
      const kind = url.searchParams.get("kind");
      const runs = [processesRun, filesRun].filter((r) => !kind || r.kind === kind);
      return route.fulfill({ json: { runs } satisfies S["RunPage"] });
    }
    const run = /^\/runs\/([^/]+)$/.exec(path);
    if (run) {
      const detail = runDetails[decodeURIComponent(run[1] ?? "")];
      return detail ? route.fulfill({ json: detail }) : fail(route, 404, "Execução não encontrada");
    }
    if (path === "/findings") return route.fulfill({ json: { findings: [criticalFinding, processFinding] } satisfies S["FindingPage"] });
    if (path === `/findings/${criticalFinding.id}`) return route.fulfill({ json: findingDetail });
    if (path === "/exceptions") return route.fulfill({ json: exceptions });
    if (path === "/schedules") return route.fulfill({ json: schedules });
    if (path === "/resources") return route.fulfill({ json: resources });
    if (path === "/engines") return route.fulfill({ json: engines });
    if (path === "/inventory/processes") return route.fulfill({ json: processInventory });
    if (path === "/inventory/persistence") return route.fulfill({ json: persistenceInventory });
    if (path === "/users") return route.fulfill({ json: users });
    if (path === "/tokens") return route.fulfill({ json: tokens });
    if (path === "/audit") return route.fulfill({ json: audit });
    if (path === "/backups") return route.fulfill({ json: backups });
    return fail(route, 404, `Rota não simulada: ${path}`);
  });
}

/** Espera as consultas secundárias da tela (painéis com "Carregando…") terminarem antes de avaliar. */
async function expectLoaded(page: Page) {
  await expect(page.getByText(/^Carregando/)).toHaveCount(0);
}

async function expectNoViolations(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const summary = results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
  expect(summary).toEqual([]);
}

// `ready` vem dos arquivos de tradução (src/i18n/pt-BR*.json) ou dos dados simulados: só aparece com a tela carregada.
const pages: { name: string; path: string; mock?: Mock; ready: string }[] = [
  { name: "visão geral", path: "/", ready: "Capacidades do sistema" },
  { name: "visão geral sem executor", path: "/", mock: { mode: "degraded" }, ready: "não consegue falar com o executor" },
  { name: "visão geral sem serviço", path: "/", mock: { mode: "offline" }, ready: "Sem resposta do serviço do VigiaHost" },
  { name: "achados", path: "/achados", ready: "PHP_Webshell_Generic" },
  { name: "detalhe do achado", path: `/achados/${criticalFinding.id}`, ready: location.path },
  { name: "exceções", path: "/excecoes", ready: "Biblioteca legítima do tema" },
  { name: "execuções", path: "/execucoes", ready: FILES_RUN },
  { name: "detalhe da execução", path: `/execucoes/${FILES_RUN}`, ready: "clamav" },
  { name: "cobertura", path: "/cobertura", ready: "Última verificação de arquivos" },
  { name: "processos", path: "/processos", ready: "kworkerd" },
  { name: "persistência", path: "/processos?aba=persistencia", ready: "/var/spool/cron/loja" },
  { name: "agendamentos", path: "/agendamentos", ready: "Varredura noturna" },
  { name: "recursos", path: "/recursos", ready: "noturno" },
  { name: "motores", path: "/motores", ready: "Assinaturas com mais de 3 dias" },
  { name: "usuários", path: "/usuarios", ready: "Equipe de suporte" },
  { name: "tokens", path: "/tokens", ready: "Monitoramento Zabbix" },
  { name: "auditoria", path: "/auditoria", ready: "198.51.100.20" },
  { name: "backup", path: "/backup", ready: "vigiahost-20261022-030000.db" },
  { name: "configurações", path: "/configuracoes", ready: "Aparência" },
  { name: "catálogo", path: "/catalogo", ready: "ConfirmDialog" },
  { name: "página planejada", path: "/regras", ready: "Planejada · 1A" },
  { name: "página inexistente", path: "/nao-existe", ready: "Ir para a visão geral" },
  { name: "login", path: "/", mock: { session: "anonymous" }, ready: "Não sou um robô" },
  { name: "login sem HTTPS", path: "/", mock: { session: "insecure" }, ready: "Esta conexão não é HTTPS" },
  { name: "segundo fator", path: "/", mock: { session: "password" }, ready: "Confirmar código" },
  { name: "recuperar senha", path: "/recuperar", mock: { session: "anonymous" }, ready: "Não sou um robô" },
];

for (const scheme of ["light", "dark"] as const) {
  test.describe(`tema ${scheme === "light" ? "claro" : "escuro"}`, () => {
    test.use({ colorScheme: scheme });
    for (const p of pages) {
      test(`${p.name} sem violações de acessibilidade`, async ({ page }) => {
        await mockApi(page, p.mock);
        await page.goto(p.path);
        await expect(page.getByText(p.ready).first()).toBeVisible();
        await expectLoaded(page);
        await expectNoViolations(page);
      });
    }

    test("diálogo de confirmação aberto sem violações", async ({ page }) => {
      await mockApi(page);
      await page.goto("/catalogo");
      await page.getByRole("button", { name: "Abrir confirmação com senha" }).click();
      await expect(page.getByRole("dialog", { name: "Criar exceção global?" })).toBeVisible();
      await expectNoViolations(page);
    });
  });
}

test("sem sessão, a raiz mostra o login com foco no título", async ({ page }) => {
  await mockApi(page, { session: "anonymous" });
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "Entrar no VigiaHost" })).toBeFocused();
  await expect(page).toHaveTitle("Entrar no VigiaHost · VigiaHost");
  await expect(page.getByRole("navigation", { name: "Principal" })).toHaveCount(0);
  await page.getByRole("link", { name: "Redefinir com o token do servidor" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Redefinir senha" })).toBeFocused();
});

test("link para pular a navegação é o primeiro foco e leva ao conteúdo", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");
  await expect(page.getByText("Capacidades do sistema")).toBeVisible();
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Pular para o conteúdo" });
  await expect(skip).toBeFocused();
  await expect(skip).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page.locator("main")).toBeFocused();
});

test("navegar move o foco para o título da nova página", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");
  await page.getByRole("link", { name: "Configurações" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Configurações" })).toBeFocused();
  await expect(page).toHaveTitle("Configurações · VigiaHost");
});

test("diálogo fecha com Esc e devolve o foco a quem o abriu", async ({ page }) => {
  await mockApi(page);
  await page.goto("/catalogo");
  const opener = page.getByRole("button", { name: "Abrir confirmação simples" });
  await opener.click();
  const dialog = page.getByRole("dialog", { name: "Mover para quarentena?" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Cancelar" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(opener).toBeFocused();
});

test("escolha de tema vale na hora e persiste após recarregar", async ({ page }) => {
  await mockApi(page);
  await page.emulateMedia({ colorScheme: "light" });
  await page.goto("/configuracoes");
  await page.getByLabel("Escuro").check();
  const scheme = () => page.evaluate(() => getComputedStyle(document.documentElement).colorScheme);
  await expect.poll(scheme).toBe("dark");
  await page.reload();
  await expect.poll(scheme).toBe("dark");
  await page.getByLabel(/Sistema/).check();
  await expect.poll(scheme).toBe("light dark");
  expect(await page.evaluate(() => localStorage.getItem("vigiahost.color-scheme"))).toBeNull();
});

const reflow: { path: string; mock?: Mock }[] = [
  { path: "/" },
  { path: "/achados" },
  { path: `/achados/${criticalFinding.id}` },
  { path: "/execucoes" },
  { path: `/execucoes/${FILES_RUN}` },
  { path: "/processos" },
  { path: "/auditoria" },
  { path: "/catalogo" },
  { path: "/configuracoes" },
  { path: "/", mock: { session: "anonymous" } },
];

for (const r of reflow) {
  const label = r.mock?.session === "anonymous" ? `${r.path} (login)` : r.path;
  test(`sem rolagem horizontal em 320 px: ${label}`, async ({ page }) => {
    await mockApi(page, r.mock);
    await page.setViewportSize({ width: 320, height: 640 });
    await page.goto(r.path);
    await expect(page.locator("h1")).toBeVisible();
    await expectLoaded(page);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  });
}

test("menu móvel abre, mostra a navegação e fecha ao navegar", async ({ page }) => {
  await mockApi(page);
  await page.setViewportSize({ width: 375, height: 700 });
  await page.goto("/");
  const toggle = page.getByRole("button", { name: "Abrir menu" });
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByRole("navigation", { name: "Principal" })).toBeHidden();
  await toggle.click();
  await expect(page.getByRole("button", { name: "Fechar menu" })).toHaveAttribute("aria-expanded", "true");
  await page.getByRole("link", { name: "Configurações" }).click();
  await expect(page.getByRole("navigation", { name: "Principal" })).toBeHidden();
});
