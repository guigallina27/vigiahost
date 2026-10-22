import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Schemas } from "../../api/client";
import enAccounts from "../../i18n/en/accounts.json";
import ptAccounts from "../../i18n/pt-BR/accounts.json";
import { buildScheduleInput, emptyScheduleValues, valuesFromSchedule, type Schedule } from "../config/schedules";
import { filtersToParams, filtersToQuery, parseFilters, withoutAccount } from "../findings/filters";
import { buildRunCreate, filtersFromSearch, filtersToQuery as runFiltersToQuery } from "../runs/runFormat";
import {
  accountFiltersToParams,
  buildAccountsRun,
  choiceToSelection,
  compareRisk,
  filterAccounts,
  parseAccountFilters,
  parseUid,
  persistenceOf,
  processesOf,
  selectionToChoice,
  sortAccounts,
  toggleUid,
  visibleAccounts,
  type Account,
} from "./accounts";
import { AccountsPage } from "./AccountsPage";

beforeAll(() => {
  // O jsdom não implementa o modo modal do <dialog>; basta simular a abertura e o fechamento.
  HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
    this.setAttribute("open", "");
  };
  HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
    this.removeAttribute("open");
    this.dispatchEvent(new Event("close"));
  };
});

afterEach(() => vi.unstubAllGlobals());

const zero = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };

function account(uid: number, name: string, patch: Partial<Account> = {}): Account {
  return {
    uid,
    name,
    home: `/home/${name}`,
    shell: "/bin/bash",
    system: false,
    home_ok: true,
    open_findings: { ...zero },
    processes: 0,
    persistence_items: 0,
    ...patch,
  };
}

const loja = account(1001, "loja", {
  open_findings: { critical: 1, high: 2, medium: 0, low: 0, info: 0, total: 3 },
  last_run: {
    id: "r-loja",
    status: "completed",
    created_at: "2026-10-21T03:00:00Z",
    finished_at: "2026-10-21T03:10:00Z",
    files_processed: 900,
    files_eligible: 1000,
  },
  processes: 4,
  persistence_items: 2,
});
const blog = account(1002, "blog", { open_findings: { critical: 0, high: 5, medium: 1, low: 0, info: 0, total: 6 } });
const api = account(1003, "api", {
  open_findings: { critical: 1, high: 2, medium: 0, low: 0, info: 1, total: 4 },
  last_run: { id: "r-api", status: "running", created_at: "2026-10-22T09:00:00Z", files_processed: 1, files_eligible: 2 },
});
const vazio = account(1004, "vazio", { home_ok: false, processes: -1, persistence_items: -1 });

describe("filtros da lista de contas", () => {
  it("lê do endereço, ignora ordenação desconhecida e omite o padrão ao escrever", () => {
    const f = parseAccountFilters(new URLSearchParams("q=%20loja%20&system=1&findings=1&sort=uid"));
    expect(f).toEqual({ q: "loja", system: true, withFindings: true, sort: "uid" });
    expect(accountFiltersToParams(f).toString()).toBe("q=loja&system=1&findings=1&sort=uid");
    const d = parseAccountFilters(new URLSearchParams("sort=xyz&system=sim"));
    expect(d).toEqual({ q: "", system: false, withFindings: false, sort: "risk" });
    expect(accountFiltersToParams(d).toString()).toBe("");
  });

  it("busca por nome, UID ou diretório e filtra só com achados abertos", () => {
    const list = [loja, blog, api, vazio];
    expect(filterAccounts(list, { q: "BLO", withFindings: false }).map((a) => a.name)).toEqual(["blog"]);
    expect(filterAccounts(list, { q: "1003", withFindings: false }).map((a) => a.name)).toEqual(["api"]);
    expect(filterAccounts(list, { q: "/home/va", withFindings: false }).map((a) => a.name)).toEqual(["vazio"]);
    expect(filterAccounts(list, { q: "", withFindings: true }).map((a) => a.name)).toEqual(["loja", "blog", "api"]);
  });
});

describe("ordenação", () => {
  it("risco: críticos, depois altos, médios..., total e nome", () => {
    // loja e api empatam em crítico e alto; api tem 1 informativo a mais.
    expect(sortAccounts([vazio, blog, loja, api], "risk").map((a) => a.name)).toEqual(["api", "loja", "blog", "vazio"]);
    const a = account(10, "b", { open_findings: { ...zero, low: 1, total: 1 } });
    const b = account(11, "a", { open_findings: { ...zero, low: 1, total: 1 } });
    expect(compareRisk(a, b)).toBeGreaterThan(0);
  });

  it("nome, UID e última verificação (nunca verificadas no fim)", () => {
    const list = [vazio, blog, loja, api];
    expect(sortAccounts(list, "name").map((a) => a.name)).toEqual(["api", "blog", "loja", "vazio"]);
    expect(sortAccounts(list, "uid").map((a) => a.uid)).toEqual([1001, 1002, 1003, 1004]);
    expect(sortAccounts(list, "lastRun").map((a) => a.name)).toEqual(["api", "loja", "blog", "vazio"]);
    expect(list.map((a) => a.name)).toEqual(["vazio", "blog", "loja", "api"]);
  });

  it("5.000 contas filtram e ordenam bem abaixo de 2 s", () => {
    const many = Array.from({ length: 5000 }, (_, i) =>
      account(2000 + i, `conta${i}`, { open_findings: { ...zero, high: i % 7, low: i % 3, total: (i % 7) + (i % 3) } }),
    );
    const start = performance.now();
    const rows = visibleAccounts(many, { q: "conta1", system: false, withFindings: true, sort: "risk" });
    expect(performance.now() - start).toBeLessThan(500);
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0]?.open_findings.high).toBe(6);
  });
});

describe("pedidos de verificação", () => {
  it("todas as contas ou UIDs sem repetição, em ordem", () => {
    expect(buildAccountsRun({ kind: "all" })).toEqual({ kind: "files", incremental: true, accounts: { all: true } });
    expect(buildAccountsRun({ kind: "uids", uids: [1003, 1001, 1003, -1] })).toEqual({
      kind: "files",
      incremental: true,
      accounts: { uids: [1001, 1003] },
    });
    expect(toggleUid([1001], 1002)).toEqual([1001, 1002]);
    expect(toggleUid([1001, 1002], 1001)).toEqual([1002]);
  });

  it("converte a escolha do formulário para o contrato e de volta", () => {
    expect(choiceToSelection({ mode: "none", uids: [1001] })).toBeUndefined();
    expect(choiceToSelection({ mode: "all", uids: [1001] })).toEqual({ all: true });
    expect(choiceToSelection({ mode: "selected", uids: [] })).toBeUndefined();
    expect(choiceToSelection({ mode: "selected", uids: [5, 2, 5] })).toEqual({ uids: [2, 5] });
    expect(selectionToChoice(undefined)).toEqual({ mode: "none", uids: [] });
    expect(selectionToChoice({ all: true })).toEqual({ mode: "all", uids: [] });
    expect(selectionToChoice({ uids: [7] })).toEqual({ mode: "selected", uids: [7] });
  });

  it("nova verificação: caminhos opcionais com contas, contas escolhidas exigem ao menos uma", () => {
    const base = { kind: "files" as const, paths: "", exclude: "", incremental: true, profile: "" };
    expect(buildRunCreate({ ...base, accounts: { mode: "all", uids: [] } })).toEqual({
      ok: true,
      body: { kind: "files", incremental: true, accounts: { all: true } },
    });
    expect(buildRunCreate({ ...base, paths: "/var/www", accounts: { mode: "selected", uids: [1002, 1001] } })).toEqual({
      ok: true,
      body: { kind: "files", incremental: true, paths: ["/var/www"], accounts: { uids: [1001, 1002] } },
    });
    expect(buildRunCreate({ ...base, accounts: { mode: "selected", uids: [] } })).toEqual({
      ok: false,
      error: { field: "accounts", code: "accountsRequired" },
    });
    expect(buildRunCreate({ ...base, accounts: { mode: "none", uids: [] } })).toEqual({
      ok: false,
      error: { field: "paths", code: "pathsRequired" },
    });
  });

  it("agendamento de arquivos leva as contas; o de processos não", () => {
    const values = { ...emptyScheduleValues("UTC"), name: "Contas", accounts: { mode: "all" as const, uids: [] } };
    expect(buildScheduleInput(values)).toMatchObject({ paths: [], accounts: { all: true } });
    expect(buildScheduleInput({ ...values, kind: "processes" })).not.toHaveProperty("accounts");
    expect(buildScheduleInput(emptyScheduleValues("UTC"))).not.toHaveProperty("accounts");
    const saved: Schedule = {
      id: 1,
      name: "Contas de risco",
      kind: "files",
      cron: "0 3 * * *",
      timezone: "UTC",
      paths: [],
      accounts: { uids: [1001] },
      exclude: [],
      incremental: true,
      profile: "padrao",
      missed_policy: "skip",
      enabled: true,
      created_by: "op",
      created_at: "2026-10-01T12:00:00Z",
      updated_at: "2026-10-01T12:00:00Z",
      upcoming: [],
    };
    expect(valuesFromSchedule(saved).accounts).toEqual({ mode: "selected", uids: [1001] });
  });
});

describe("filtro de conta nas outras listas", () => {
  it("achados aceitam ?account= e repassam à API", () => {
    const f = parseFilters(new URLSearchParams("account=1001&severity=critical"));
    expect(f.account).toBe(1001);
    expect(filtersToQuery(f)).toMatchObject({ account: 1001, severity: ["critical"] });
    expect(filtersToParams(f).get("account")).toBe("1001");
    expect(filtersToQuery(withoutAccount(f))).not.toHaveProperty("account");
    expect(parseFilters(new URLSearchParams("account=-1")).account).toBeUndefined();
  });

  it("execuções aceitam ?account=", () => {
    const f = filtersFromSearch(new URLSearchParams("account=1001&kind=files"));
    expect(f).toEqual({ kind: "files", account: 1001 });
    expect(runFiltersToQuery(f)).toEqual({ kind: "files", account: 1001 });
    expect(parseUid("abc")).toBeUndefined();
    expect(parseUid("4294967296")).toBeUndefined();
    expect(parseUid("0")).toBe(0);
  });
});

describe("inventário da conta", () => {
  it("processos pelo UID; persistência pelo dono ou pelo caminho no diretório pessoal", () => {
    const procs = [
      { pid: 1, ppid: 0, uid: 0, comm: "init", exe: "/sbin/init", cpu_percent: 0, rss_bytes: 0, threads: 1 },
      { pid: 2, ppid: 1, uid: 1001, comm: "php", exe: "/usr/bin/php", cpu_percent: 0, rss_bytes: 0, threads: 1 },
    ];
    expect(processesOf(loja, procs).map((p) => p.pid)).toEqual([2]);
    const items: Schemas["PersistenceEntry"][] = [
      { kind: "cron", path: "/var/spool/cron/loja", owner: "loja" },
      { kind: "authorized-keys", path: "/home/loja/.ssh/authorized_keys", owner: "root" },
      { kind: "cron", path: "/home/lojaantiga/x", owner: "root" },
      { kind: "cron", path: "/var/spool/cron/blog", owner: "blog" },
      { kind: "cron", path: "/var/spool/cron/old", owner: "1001", change: "removed" },
    ];
    expect(persistenceOf(loja, items).map((e) => e.path)).toEqual(["/var/spool/cron/loja", "/home/loja/.ssh/authorized_keys"]);
    // Sem diretório pessoal válido, só o dono conta.
    expect(persistenceOf({ ...loja, home_ok: false }, items).map((e) => e.path)).toEqual(["/var/spool/cron/loja"]);
  });
});

describe("traduções da área de contas", () => {
  function keys(obj: object, prefix = ""): string[] {
    return Object.entries(obj).flatMap(([k, v]) =>
      typeof v === "object" && v !== null ? keys(v, `${prefix}${k}.`) : [`${prefix}${k}`],
    );
  }
  it("mesmas chaves nos dois idiomas", () => {
    expect(keys(enAccounts).sort()).toEqual(keys(ptAccounts).sort());
  });
});

// --- Fluxo da tela ---

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

function LocationProbe() {
  const { search } = useLocation();
  return <output data-testid="search">{search}</output>;
}

type Posted = { body: unknown; key: string | null };

function mockApi(list: Account[], opts: { status?: number } = {}) {
  const posts: Posted[] = [];
  const gets: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      const url = new URL(req.url);
      if (req.method === "GET") gets.push(`${url.pathname}${url.search}`);
      if (url.pathname === "/api/v1/accounts") {
        if (opts.status) return json({ error: "executor indisponível" }, opts.status);
        return json({ uid_min: 1000, uid_max: 60000, accounts: list } satisfies Schemas["AccountList"]);
      }
      if (req.method === "POST" && url.pathname === "/api/v1/runs") {
        posts.push({ body: await req.json(), key: req.headers.get("Idempotency-Key") });
        return json({ id: "r-contas-1" }, 201);
      }
      return json({ error: "inesperado" }, 500);
    }),
  );
  return { posts, gets };
}

function renderPage(role: Schemas["Role"] = "operator", entry = "/contas") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  qc.setQueryData(["session"], session(role));
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route
            path="/contas"
            element={
              <>
                <AccountsPage />
                <LocationProbe />
              </>
            }
          />
          <Route path="/execucoes/:runId" element={<p>detalhe da execução aberto</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function rowNames() {
  const table = screen.getByRole("table");
  return within(table)
    .getAllByRole("row")
    .slice(1)
    .map((r) => within(r).getAllByRole("link")[0]?.textContent);
}

describe("AccountsPage", () => {
  it("lista por risco e verifica todas as contas com chave de idempotência", async () => {
    const user = userEvent.setup();
    const { posts } = mockApi([vazio, blog, loja, api]);
    renderPage();
    expect(await screen.findByRole("table")).toBeInTheDocument();
    expect(rowNames()).toEqual(["api", "loja", "blog", "vazio"]);
    expect(screen.getByText(/Diretório pessoal ausente/)).toBeInTheDocument();
    expect(screen.getAllByText("Sem inspeção ainda")).toHaveLength(2);
    expect(screen.getAllByText("Nunca verificada")).toHaveLength(2);

    await user.click(screen.getByRole("button", { name: "Verificar todas as contas" }));
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveTextContent("/tmp, /var/tmp e /dev/shm");
    expect(dialog).toHaveTextContent("4 na lista agora");
    await user.click(within(dialog).getByRole("button", { name: "Iniciar verificação" }));

    expect(await screen.findByText("detalhe da execução aberto")).toBeInTheDocument();
    expect(posts).toEqual([{ body: { kind: "files", incremental: true, accounts: { all: true } }, key: expect.any(String) }]);
  });

  it("verifica uma conta pela linha e várias pela seleção", async () => {
    const user = userEvent.setup();
    const { posts } = mockApi([loja, blog, api]);
    renderPage();
    await screen.findByRole("table");

    await user.click(screen.getByRole("checkbox", { name: "Selecionar blog" }));
    await user.click(screen.getByRole("checkbox", { name: "Selecionar api" }));
    expect(screen.getByText("2 contas selecionadas")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Verificar selecionadas" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByRole("heading")).toHaveTextContent("Verificar 2 contas?");
    await user.click(within(dialog).getByRole("button", { name: "Cancelar" }));
    expect(posts).toHaveLength(0);

    await user.click(screen.getByRole("button", { name: "Verificar conta loja" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Iniciar verificação" }));
    expect(await screen.findByText("detalhe da execução aberto")).toBeInTheDocument();
    expect(posts.map((p) => p.body)).toEqual([{ kind: "files", incremental: true, accounts: { uids: [1001] } }]);
  });

  it("guarda a busca e os filtros no endereço e filtra no cliente", async () => {
    const user = userEvent.setup();
    const { gets } = mockApi([loja, blog, api, vazio]);
    renderPage();
    await screen.findByRole("table");

    await user.type(screen.getByLabelText("Buscar conta"), "blo");
    await waitFor(() => expect(rowNames()).toEqual(["blog"]));
    await waitFor(() => expect(screen.getByTestId("search")).toHaveTextContent("?q=blo"));

    await user.clear(screen.getByLabelText("Buscar conta"));
    await user.click(screen.getByLabelText("Só com achados abertos"));
    await waitFor(() => expect(rowNames()).toEqual(["api", "loja", "blog"]));
    await user.selectOptions(screen.getByLabelText("Ordenar por"), "name");
    await waitFor(() => expect(rowNames()).toEqual(["api", "blog", "loja"]));
    // A busca vazia é gravada depois da pausa e não pode desfazer os filtros marcados nesse meio-tempo.
    await new Promise((r) => setTimeout(r, 400));
    await waitFor(() => expect(screen.getByTestId("search")).toHaveTextContent("?findings=1&sort=name"));

    await user.click(screen.getByLabelText("Incluir contas de sistema"));
    await waitFor(() => expect(gets).toContain("/api/v1/accounts?system=true"));
  });

  it("sem contas de hospedagem, sugere incluir as de sistema", async () => {
    const user = userEvent.setup();
    const { gets } = mockApi([]);
    renderPage();
    expect(await screen.findByText("Nenhuma conta de hospedagem encontrada")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Incluir contas de sistema" }));
    await waitFor(() => expect(gets).toContain("/api/v1/accounts?system=true"));
  });

  it("executor fora do ar: explica e mostra onde conferir", async () => {
    mockApi([], { status: 503 });
    renderPage();
    expect(await screen.findByText("Executor indisponível")).toBeInTheDocument();
    expect(screen.getByText("systemctl status vigiahost-executor")).toBeInTheDocument();
  });

  it("perfil de leitura vê a lista sem as ações", async () => {
    mockApi([loja]);
    renderPage("reader");
    await screen.findByRole("table");
    expect(screen.queryByRole("button", { name: "Verificar todas as contas" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Verificar conta/ })).toBeNull();
    expect(within(screen.getByRole("table")).queryByRole("checkbox")).toBeNull();
  });
});
