import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Schemas } from "../../api/client";
import enSystem from "../../i18n/en/system.json";
import ptSystem from "../../i18n/pt-BR/system.json";
import { subjectLabel } from "../findings/filters";
import { HiddenPanel, hiddenCount } from "../inventory/HiddenPanel";
import { buildRunCreate } from "../runs/runFormat";
import { IntegrityPage } from "./IntegrityPage";
import {
  cacheState,
  expectedTools,
  ignoredEntries,
  packageText,
  severityCounts,
  sortUpdates,
  systemFindingsHref,
  updateTone,
  type IntegrityReport,
  type UpdatesReport,
} from "./systemFormat";
import { UpdatesPage } from "./UpdatesPage";

afterEach(() => vi.unstubAllGlobals());

// Relatório real do laboratório (AlmaLinux 9 em WSL): grupos perdidos na importação e /etc/hostname alterado.
const integrity: IntegrityReport = {
  run_id: "20261022-233552-aa11bb22",
  taken_at: "2026-10-22T23:35:52Z",
  runs: [
    { run_id: "20261022-233552-aa11bb22", taken_at: "2026-10-22T23:35:52Z" },
    { run_id: "20261021-030000-cc33dd44", taken_at: "2026-10-21T03:00:00Z" },
  ],
  manager: "rpm",
  tools: ["rpm -Va"],
  debsums_available: false,
  packages: 317,
  differences: 8,
  ignored: { directory: 4 },
  by_severity: { high: 3, info: 1 },
  files: [
    {
      path: "/usr/bin/write",
      flags: "......G..",
      changes: ["group"],
      class: "binary",
      severity: "high",
      signature: "integridade.permissoes_alteradas",
      description: "permissões especiais",
      packages: [{ name: "util-linux", version: "2.37.4-25.el9", arch: "x86_64" }],
    },
    {
      path: "/etc/hostname",
      flags: ".M.......",
      changes: ["mode"],
      config: true,
      class: "config",
      severity: "info",
      signature: "integridade.permissoes_alteradas",
      description: "dono ou permissões",
      packages: [{ name: "systemd", version: "252-67.el9_8.2.alma.1", arch: "x86_64" }],
    },
  ],
  signatures: {
    manager: "rpm",
    method: "package",
    signed: 315,
    unsigned: [{ name: "clamav", version: "1.4.6-1", arch: "x86_64" }],
    repos: [
      { id: "baseos", file: "/etc/yum.repos.d/almalinux-baseos.repo", enabled: true, verified: true },
      { id: "terceiro", file: "/etc/yum.repos.d/terceiro.repo", enabled: true, verified: false, problem: "gpgcheck_off" },
    ],
  },
  seconds: 1.6,
};

const updates: UpdatesReport = {
  run_id: "20261022-233600-ee55ff66",
  taken_at: "2026-10-22T23:36:00Z",
  runs: [{ run_id: "20261022-233600-ee55ff66", taken_at: "2026-10-22T23:36:00Z" }],
  manager: "rpm",
  cache_updated_at: "2026-10-22T17:51:38Z",
  refresh_allowed: false,
  refreshed: false,
  security: [
    { name: "pcre2", arch: "x86_64", installed: "10.40-6.el9", available: "10.40-7.el9_8", security: true, severity: "moderate", advisories: ["ALSA-2026:81532"], cves: ["CVE-2026-86145"] },
    { name: "openssl", arch: "x86_64", installed: "1:3.5.8-1.el9_8", available: "1:3.5.8-2.el9_8", security: true, severity: "important", advisories: ["ALSA-2026:77396"], cves: ["CVE-2026-84782"] },
  ],
  other: [{ name: "tzdata", arch: "noarch", installed: "2026c-1.el9", available: "2026e-1.el9", security: false }],
  by_severity: { important: 1, moderate: 1 },
  reboot: { known: true, required: false, running_kernel: "6.6.114.1-microsoft-standard-WSL2" },
  services: [{ unit: "vh-e22-restart.service", pids: [209125], files: ["/opt/vh-e22-test/libz-test.so"], source: "maps" }],
  processes: [],
  tools: { dnf: true },
  seconds: 2.4,
};

describe("regras das telas do sistema", () => {
  it("conta por gravidade, ignora motivos desconhecidos e monta textos de pacote", () => {
    expect(severityCounts({ high: 3, info: 1, bogus: 9 })).toEqual({ critical: 0, high: 3, medium: 0, low: 0, info: 1, total: 4 });
    expect(ignoredEntries({ directory: 4, outro: 2, doc: 1 })).toEqual([
      ["doc", 1],
      ["directory", 4],
    ]);
    expect(packageText({ name: "bash", version: "5.2.15-2+b8", arch: "amd64" })).toBe("bash-5.2.15-2+b8.amd64");
    expect(packageText({ name: "vigiahost", version: "0.1.7-1" })).toBe("vigiahost-0.1.7-1");
    expect(systemFindingsHref("updates")).toBe("/achados?category=update");
  });

  it("ordena correções pela gravidade e classifica a lista de pacotes", () => {
    expect(sortUpdates(updates.security).map((u) => u.name)).toEqual(["openssl", "pcre2"]);
    expect(updateTone("important")).toBe("high");
    expect(updateTone(undefined)).toBe("neutral");
    const now = new Date("2026-10-23T00:00:00Z");
    expect(cacheState(updates, now)).toBe("fresh");
    expect(cacheState({ cache_updated_at: "2026-10-10T00:00:00Z" }, now)).toBe("stale");
    expect(cacheState({}, now)).toBe("never");
    expect(expectedTools("dpkg").map((t) => t.name)).toEqual(["apt", "needrestart"]);
  });

  it("verificações do sistema não mandam caminhos nem contas", () => {
    const built = buildRunCreate({ kind: "integrity", paths: "/etc", exclude: "", incremental: true, profile: "padrao" });
    expect(built).toEqual({ ok: true, body: { kind: "integrity", incremental: false, profile: "padrao" } });
  });

  it("traduz o assunto dos achados do sistema", () => {
    expect(subjectLabel("security-updates")).toEqual({ key: "securityUpdates" });
    expect(subjectLabel("repo:epel")).toEqual({ key: "repo", id: "epel" });
    expect(subjectLabel("tcp/31337")).toEqual({ key: "port", proto: "TCP", port: "31337" });
    expect(subjectLabel("pid:4242")).toEqual({ key: "pid", pid: "4242" });
    expect(subjectLabel("algo-novo")).toEqual({ key: "raw", text: "algo-novo" });
  });

  it("mesmas chaves de tradução nos dois idiomas", () => {
    function keys(o: object, prefix = ""): string[] {
      return Object.entries(o).flatMap(([k, v]) => (typeof v === "object" && v !== null ? keys(v, `${prefix}${k}.`) : [`${prefix}${k}`]));
    }
    expect(keys(enSystem).sort()).toEqual(keys(ptSystem).sort());
  });
});

describe("HiddenPanel", () => {
  it("diz que nada está oculto com o que foi conferido", () => {
    render(
      <HiddenPanel
        report={{
          processes: { checked: true, pid_max: 4194304, visible: 312, found: [], discarded: 0 },
          ports: { checked: true, probed: 131018, skipped: 0, listed: 12, netlink: true, found: [], discarded: 1 },
          seconds: 3,
        }}
      />,
    );
    expect(screen.getByText(/Nada oculto/)).toHaveTextContent("312");
    expect(screen.getByText("Nenhum item oculto")).toBeInTheDocument();
    expect(screen.getByText(/1 candidatos descartados/)).toBeInTheDocument();
  });

  it("lista processo e porta ocultos em tabelas e avisa quando a busca não rodou", () => {
    const report: Schemas["HiddenReport"] = {
      processes: { checked: true, pid_max: 4194304, visible: 300, found: [{ pid: 4242, checks: ["getsid", "kill"], direct_access: true, comm: "kworkerx" }], discarded: 0 },
      ports: { checked: true, probed: 1000, skipped: 0, listed: 3, netlink: true, found: [{ proto: "tcp", port: 31337, reason: "bind_only" }], discarded: 0 },
      seconds: 1,
    };
    expect(hiddenCount(report)).toBe(2);
    const { unmount } = render(<HiddenPanel report={report} />);
    expect(screen.getByText("2 itens ocultos confirmados duas vezes")).toBeInTheDocument();
    expect(screen.getByRole("table", { name: /Processos que respondem/ })).toHaveTextContent("4242");
    expect(screen.getByRole("table", { name: /Portas em uso/ })).toHaveTextContent("TCP 31337");
    unmount();
    render(<HiddenPanel report={undefined} />);
    expect(screen.getByText(/não rodou nesta inspeção/)).toBeInTheDocument();
  });
});

// --- Fluxo das telas ---

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function session(role: Schemas["Role"]): Schemas["Session"] {
  return {
    authenticated: true,
    setup_required: false,
    secure_transport: true,
    stage: "full",
    user: { id: 7, username: "op", display_name: "Operadora", role, mfa_enabled: false },
  };
}

function mockApi(routes: Record<string, () => Response>) {
  const posts: unknown[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      const url = new URL(req.url);
      if (req.method === "POST" && url.pathname === "/api/v1/runs") {
        posts.push(await req.json());
        return json({ id: "r-nova", kind: "integrity", status: "queued" }, 201);
      }
      if (url.pathname === "/api/v1/runs") return json({ runs: [] } satisfies Schemas["RunPage"]);
      const handler = routes[`${url.pathname}${url.search}`] ?? routes[url.pathname];
      return handler ? handler() : json({ error: "inesperado" }, 500);
    }),
  );
  return posts;
}

function LocationProbe() {
  const { search } = useLocation();
  return <output data-testid="search">{search}</output>;
}

function renderAt(entry: string, role: Schemas["Role"] = "operator") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  qc.setQueryData(["session"], session(role));
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route path="/integridade" element={<><IntegrityPage /><LocationProbe /></>} />
          <Route path="/atualizacoes" element={<UpdatesPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("IntegrityPage", () => {
  it("mostra arquivos, assinaturas e troca de relatório pelo histórico", async () => {
    const user = userEvent.setup();
    mockApi({ "/api/v1/integrity": () => json(integrity) });
    renderAt("/integridade");
    const files = await screen.findByRole("table", { name: /Arquivos diferentes do pacote/ });
    const rows = within(files).getAllByRole("row");
    expect(rows[1]).toHaveTextContent("/usr/bin/write");
    expect(rows[1]).toHaveTextContent("util-linux-2.37.4-25.el9.x86_64");
    expect(rows[1]).toHaveTextContent("grupo");
    expect(rows[2]).toHaveTextContent("arquivo de configuração");
    const repos = screen.getByRole("table", { name: /Repositórios configurados/ });
    expect(within(repos).getByText("gpgcheck desligado")).toBeInTheDocument();
    expect(screen.getByText("clamav-1.4.6-1.x86_64")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Verificação exibida"), "20261021-030000-cc33dd44");
    expect(screen.getByTestId("search")).toHaveTextContent("execucao=20261021-030000-cc33dd44");
  });

  it("sem relatório, o operador inicia a primeira verificação", async () => {
    const user = userEvent.setup();
    const posts = mockApi({ "/api/v1/integrity": () => json({ error: "nenhuma verificação" }, 404) });
    renderAt("/integridade");
    expect(await screen.findByText("Nenhuma verificação de integridade ainda")).toBeInTheDocument();
    // O botão aparece no cabeçalho e no estado vazio; qualquer um pede a verificação.
    const [button] = screen.getAllByRole("button", { name: "Verificar agora" });
    if (!button) throw new Error("botão ausente");
    await user.click(button);
    await vi.waitFor(() => expect(posts).toEqual([{ kind: "integrity", profile: "padrao", incremental: false }]));
  });

  it("leitor não vê o botão e recebe a orientação", async () => {
    mockApi({ "/api/v1/integrity": () => json({ error: "nenhuma verificação" }, 404) });
    renderAt("/integridade", "reader");
    expect(await screen.findByText(/Peça a um operador/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Verificar agora" })).toBeNull();
  });
});

describe("UpdatesPage", () => {
  it("lista correções pela gravidade, serviços e explica a lista de pacotes", async () => {
    mockApi({ "/api/v1/updates": () => json(updates) });
    renderAt("/atualizacoes");
    const table = await screen.findByRole("table", { name: "Pacotes com correção de segurança pendente" });
    const rows = within(table).getAllByRole("row");
    expect(rows[1]).toHaveTextContent("openssl.x86_64");
    expect(rows[1]).toHaveTextContent("Importante");
    expect(screen.getByRole("table", { name: /Serviços que ainda usam/ })).toHaveTextContent("vh-e22-restart.service");
    expect(screen.getByText("Sem reinício pendente")).toBeInTheDocument();
    expect(screen.getByText(/refresh_package_metadata/)).toBeInTheDocument();
    // needs-restarting ausente: aparece a dica de instalação.
    expect(screen.getByText(/dnf install dnf-utils/)).toBeInTheDocument();
  });

  it("relatório de execução inexistente oferece o mais recente", async () => {
    mockApi({ "/api/v1/updates": () => json({ error: "não encontrado" }, 404) });
    renderAt("/atualizacoes?execucao=20261001-000000-00000000");
    expect(await screen.findByText("Relatório não encontrado")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Ver o relatório mais recente" })).toHaveAttribute("href", "/atualizacoes");
  });
});
