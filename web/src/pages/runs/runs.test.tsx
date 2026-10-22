import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { NewRunDialog } from "./NewRunDialog";
import {
  buildRunCreate,
  filtersFromSearch,
  filtersToQuery,
  formatBytes,
  formatDuration,
  parseLines,
  runActions,
  skipEntries,
  skippedTotal,
} from "./runFormat";

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

describe("filtros da lista", () => {
  it("lê só valores conhecidos do endereço e converte grupos em estados da API", () => {
    const f = filtersFromSearch(new URLSearchParams("status=failed&kind=files&extra=1"));
    expect(f).toEqual({ status: "failed", kind: "files" });
    expect(filtersToQuery(f)).toEqual({ status: ["failed", "engine_failure", "interrupted"], kind: "files" });
  });

  it("ignora valores inválidos e não gera chaves vazias", () => {
    const f = filtersFromSearch(new URLSearchParams("status=tudo&kind=rede"));
    expect(f).toEqual({});
    expect(filtersToQuery(f)).toEqual({});
  });
});

describe("pedido de nova verificação", () => {
  const base = { kind: "files" as const, paths: "", exclude: "", incremental: true, profile: "" };

  it("uma linha por caminho, sem vazias nem repetidas", () => {
    expect(parseLines("  /home \n\n/var/www\r\n/home\n")).toEqual(["/home", "/var/www"]);
  });

  it("monta o corpo de arquivos com exclusões e perfil", () => {
    const r = buildRunCreate({ ...base, paths: "/home\n/var/www", exclude: "/home/x/cache", profile: "leve" });
    expect(r).toEqual({
      ok: true,
      body: { kind: "files", incremental: true, profile: "leve", paths: ["/home", "/var/www"], exclude: ["/home/x/cache"] },
    });
  });

  it("omite exclusões e perfil vazios", () => {
    const r = buildRunCreate({ ...base, paths: "/home", incremental: false });
    expect(r).toEqual({ ok: true, body: { kind: "files", incremental: false, paths: ["/home"] } });
  });

  it("processos não levam caminhos", () => {
    expect(buildRunCreate({ ...base, kind: "processes", paths: "/home" })).toEqual({
      ok: true,
      body: { kind: "processes", incremental: false },
    });
  });

  it("recusa lista vazia, caminho relativo e excesso antes de enviar", () => {
    expect(buildRunCreate(base)).toEqual({ ok: false, error: { field: "paths", code: "pathsRequired" } });
    expect(buildRunCreate({ ...base, paths: "/home\nvar/www" })).toEqual({
      ok: false,
      error: { field: "paths", code: "notAbsolute", path: "var/www" },
    });
    expect(buildRunCreate({ ...base, paths: "/home", exclude: "tmp" })).toEqual({
      ok: false,
      error: { field: "exclude", code: "notAbsolute", path: "tmp" },
    });
    const many = Array.from({ length: 65 }, (_, i) => `/p${i}`).join("\n");
    expect(buildRunCreate({ ...base, paths: many })).toEqual({ ok: false, error: { field: "paths", code: "pathsTooMany", max: 64 } });
  });
});

describe("ações por estado", () => {
  it("só oferece o que o servidor aceita", () => {
    expect(runActions({ status: "queued", paused: false })).toEqual(["cancel"]);
    expect(runActions({ status: "running", paused: false })).toEqual(["pause", "limits", "cancel"]);
    expect(runActions({ status: "running", paused: true })).toEqual(["resume", "limits", "cancel"]);
    expect(runActions({ status: "completed", paused: false })).toEqual([]);
    expect(runActions({ status: "interrupted", paused: false })).toEqual([]);
  });
});

describe("motivos fora da análise", () => {
  it("ordena pelo glossário, põe desconhecidos no fim e não conta o cache", () => {
    const map = { cached: 500, zzz_novo: 2, permission: 3, too_large: 1, excluded: 0 };
    expect(skipEntries(map)).toEqual([
      { reason: "too_large", count: 1 },
      { reason: "permission", count: 3 },
      { reason: "zzz_novo", count: 2 },
    ]);
    expect(skippedTotal(map)).toBe(6);
    expect(skipEntries(undefined)).toEqual([]);
  });
});

describe("formatação", () => {
  it("duração legível no idioma ativo", () => {
    expect(formatDuration(42, "pt-BR")).toBe("42 s");
    expect(formatDuration(303, "pt-BR")).toBe("5 min 3 s");
    expect(formatDuration(8100, "pt-BR")).toBe("2 h 15 min");
  });

  it("volume em unidades decimais", () => {
    expect(formatBytes(512, "pt-BR")).toMatch(/^512\sbyte/);
    expect(formatBytes(2_500_000_000, "pt-BR")).toBe("2,5 GB");
  });
});

function renderDialog(onClose = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/execucoes"]}>
        <Routes>
          <Route path="/execucoes" element={<NewRunDialog open onClose={onClose} />} />
          <Route path="/execucoes/:runId" element={<p>detalhe aberto</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return onClose;
}

const profile = (name: string) => ({
  profile: {
    name,
    cpu_quota_percent: 200,
    memory_max_bytes: 2_000_000_000,
    io_read_bytes_per_sec: 0,
    io_weight: 100,
    workers: 4,
    clamd_concurrency: 2,
    max_runtime_sec: 0,
    nice: 10,
    max_file_bytes: 0,
  },
  custom: false,
  preset: true,
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("NewRunDialog", () => {
  it("envia o corpo com chave de idempotência e mostra a recusa do servidor", async () => {
    const user = userEvent.setup();
    const posts: { body: unknown; key: string | null }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (req: Request) => {
        if (req.url.endsWith("/api/v1/resources")) return json({ profiles: [profile("leve"), profile("padrao")] });
        if (req.method === "POST" && req.url.endsWith("/api/v1/runs")) {
          posts.push({ body: await req.json(), key: req.headers.get("Idempotency-Key") });
          return json({ error: "caminho fora da política do executor: /proc", code: "bad_request" }, 400);
        }
        return json({ error: "inesperado" }, 500);
      }),
    );
    renderDialog();

    await user.click(screen.getByRole("button", { name: "Iniciar verificação" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Informe ao menos um caminho.");
    expect(posts).toHaveLength(0);

    await user.type(screen.getByLabelText("Caminhos a verificar"), "/proc");
    expect(await screen.findByLabelText("Perfil de recursos")).toHaveValue("padrao");
    await user.click(screen.getByRole("button", { name: "Iniciar verificação" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("caminho fora da política do executor: /proc");
    expect(posts).toEqual([{ body: { kind: "files", incremental: true, profile: "padrao", paths: ["/proc"] }, key: expect.any(String) }]);
  });

  it("ao criar, fecha o diálogo e abre o detalhe da execução", async () => {
    const user = userEvent.setup();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (req: Request) => {
        if (req.url.endsWith("/api/v1/resources")) return json({ profiles: [profile("padrao")] });
        if (req.method === "POST") return json({ id: "20261022-120000-abcd1234" }, 201);
        return json({ error: "inesperado" }, 500);
      }),
    );
    const onClose = renderDialog();
    await user.click(screen.getByLabelText(/Processos e persistência/));
    expect(screen.queryByLabelText("Caminhos a verificar")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Iniciar verificação" }));
    expect(await screen.findByText("detalhe aberto")).toBeInTheDocument();
    expect(onClose).toHaveBeenCalled();
  });
});
