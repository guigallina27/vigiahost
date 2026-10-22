import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { PersistenceView } from "./PersistenceView";
import {
  filterProcesses,
  findingsLink,
  groupPersistence,
  packageState,
  parseRunId,
  sortProcesses,
  summarizeChanges,
  type PersistenceEntry,
  type ProcessInfo,
} from "./processes";
import { ProcessTable } from "./ProcessTable";
import { inspectionRequest, isActiveRun } from "./useProcessInspection";

function proc(over: Partial<ProcessInfo> & Pick<ProcessInfo, "pid">): ProcessInfo {
  return { ppid: 1, uid: 0, comm: "sshd", exe: "/usr/sbin/sshd", cpu_percent: 0, rss_bytes: 0, threads: 1, ...over };
}

const list: ProcessInfo[] = [
  proc({ pid: 10, comm: "nginx", exe: "/usr/sbin/nginx", user: "root", unit: "nginx.service", cpu_percent: 2, rss_bytes: 50 << 20, listening: ["0.0.0.0:80"] }),
  proc({ pid: 4242, comm: "kworkerds", exe: "/tmp/.x/kworkerds (deleted)", exe_deleted: true, user: "loja", cpu_percent: 97.3, rss_bytes: 10 << 20, flags: ["processo.executavel_apagado", "processo.executavel_em_temporario"], connected: ["10.0.0.5:4444"], package: "-" }),
  proc({ pid: 7, comm: "php-fpm", exe: "/usr/sbin/php-fpm", user: "www-data", unit: "php-fpm.service", cpu_percent: 2, rss_bytes: 200 << 20, package: "php-fpm" }),
];

describe("filtros e ordenação de processos", () => {
  it("busca por nome, executável, usuário, unidade e PID exato", () => {
    const f = (query: string) => filterProcesses(list, { query, onlyFlagged: false, onlyNetwork: false }).map((p) => p.pid);
    expect(f("NGINX")).toEqual([10]);
    expect(f("/tmp/")).toEqual([4242]);
    expect(f("www-data")).toEqual([7]);
    expect(f("php-fpm.service")).toEqual([7]);
    expect(f("7")).toEqual([7]); // PID exato, não "4242"/"97"
    expect(f("  ")).toHaveLength(3);
  });

  it("filtra só com marcas e só com rede, combinando com a busca", () => {
    expect(filterProcesses(list, { query: "", onlyFlagged: true, onlyNetwork: false }).map((p) => p.pid)).toEqual([4242]);
    expect(filterProcesses(list, { query: "", onlyFlagged: false, onlyNetwork: true }).map((p) => p.pid)).toEqual([10, 4242]);
    expect(filterProcesses(list, { query: "nginx", onlyFlagged: true, onlyNetwork: false })).toEqual([]);
  });

  it("ordena por CPU, memória e PID sem alterar a lista original e desempata pelo PID", () => {
    expect(sortProcesses(list, "cpu", "desc").map((p) => p.pid)).toEqual([4242, 7, 10]);
    expect(sortProcesses(list, "cpu", "asc").map((p) => p.pid)).toEqual([7, 10, 4242]);
    expect(sortProcesses(list, "memory", "desc").map((p) => p.pid)).toEqual([7, 10, 4242]);
    expect(sortProcesses(list, "pid", "asc").map((p) => p.pid)).toEqual([7, 10, 4242]);
    expect(list.map((p) => p.pid)).toEqual([10, 4242, 7]);
  });

  it("distingue executável sem pacote de pacote não consultado", () => {
    expect(packageState("-")).toBe("none");
    expect(packageState(undefined)).toBe("unknown");
    expect(packageState("")).toBe("unknown");
    expect(packageState("openssh-server")).toBe("known");
  });

  it("monta o link de achados e valida o id de execução da URL", () => {
    expect(findingsLink("processo.executavel_memfd")).toBe("/achados?q=processo.executavel_memfd");
    expect(findingsLink("a b&c")).toBe("/achados?q=a%20b%26c");
    expect(parseRunId("r-20261022-1")).toBe("r-20261022-1");
    expect(parseRunId("../x")).toBeUndefined();
    expect(parseRunId(null)).toBeUndefined();
  });

  it("pede a inspeção de processos com o perfil padrão e reconhece execução ativa", () => {
    expect(inspectionRequest()).toEqual({ kind: "processes", profile: "padrao", incremental: true });
    expect(isActiveRun("running")).toBe(true);
    expect(isActiveRun("completed")).toBe(false);
    expect(isActiveRun(undefined)).toBe(false);
  });
});

describe("ProcessTable", () => {
  it("destaca executável apagado com texto, liga marcas aos achados e filtra", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ProcessTable processes={list} />
      </MemoryRouter>,
    );
    expect(screen.getByText("Executável apagado")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: /processo\.executavel_apagado/ });
    expect(link).toHaveAttribute("href", "/achados?q=processo.executavel_apagado");
    expect(screen.getByRole("status")).toHaveTextContent("Mostrando 3 de 3 processos");

    await user.click(screen.getByLabelText("Só com marcas (1)"));
    expect(screen.getByRole("status")).toHaveTextContent("Mostrando 1 de 3 processos");
    const rows = within(screen.getByRole("table")).getAllByRole("row");
    expect(rows).toHaveLength(2); // cabeçalho + kworkerds
  });

  it("ordena pela coluna e anuncia a ordem", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ProcessTable processes={list} />
      </MemoryRouter>,
    );
    const pidHeader = screen.getByRole("columnheader", { name: /PID/ });
    expect(pidHeader).toHaveAttribute("aria-sort", "none");
    await user.click(within(pidHeader).getByRole("button"));
    expect(pidHeader).toHaveAttribute("aria-sort", "ascending");
    const firstCell = within(screen.getByRole("table")).getAllByRole("row")[1];
    expect(firstCell).toHaveTextContent(/^7/);
  });
});

describe("persistência", () => {
  const items: PersistenceEntry[] = [
    { kind: "cron", path: "/etc/cron.d/b", change: "" },
    { kind: "cron", path: "/etc/cron.d/a", change: "added" },
    { kind: "authorized-keys", path: "/root/.ssh/authorized_keys", change: "changed" },
    { kind: "novo-tipo", path: "/x" },
  ];

  it("agrupa por tipo do mais sensível ao mais comum, com tipos desconhecidos ao fim", () => {
    const g = groupPersistence(items);
    expect(g.map((x) => x.kind)).toEqual(["authorized-keys", "cron", "novo-tipo"]);
    expect(g[1]?.items.map((i) => i.path)).toEqual(["/etc/cron.d/a", "/etc/cron.d/b"]);
    expect(groupPersistence(items, true).map((x) => x.kind)).toEqual(["authorized-keys", "cron"]);
  });

  it("resume as mudanças", () => {
    expect(summarizeChanges({ items, removed: [{ kind: "sudoers", path: "/etc/sudoers.d/x", change: "removed" }] })).toEqual({
      total: 4,
      added: 1,
      changed: 1,
      removed: 1,
    });
  });

  it("explica a referência inicial e não mostra comparação", () => {
    render(<PersistenceView inventory={{ run_id: "r1", taken_at: "2026-10-22T10:00:00Z", baseline: true, items }} />);
    expect(screen.getByText(/referência inicial/)).toBeInTheDocument();
    expect(screen.queryByText("Adicionado")).toBeNull();
    expect(screen.getByRole("heading", { name: /Chaves SSH autorizadas/ })).toBeInTheDocument();
  });

  it("mostra adicionados, alterados e a lista de removidos", () => {
    render(
      <PersistenceView
        inventory={{
          run_id: "r2",
          taken_at: "2026-10-22T10:00:00Z",
          baseline: false,
          items,
          removed: [{ kind: "sudoers", path: "/etc/sudoers.d/x", change: "removed" }],
        }}
      />,
    );
    expect(screen.getByText("Adicionado")).toBeInTheDocument();
    expect(screen.getByText("Alterado")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "1 item removido desde a inspeção anterior" })).toBeInTheDocument();
  });
});
