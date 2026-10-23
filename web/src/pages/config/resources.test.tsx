import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import i18n from "i18next";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Schemas } from "../../api/client";
import { diskKey } from "./ResourcesPage";
import { pressureParts } from "./resources";
import { reasonText, suggestedProfileBody } from "./suggestion";
import { SuggestionPanel } from "./SuggestionPanel";

const t = i18n.t.bind(i18n);

beforeAll(() => {
  HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
    this.setAttribute("open", "");
  };
  HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
    this.removeAttribute("open");
    this.dispatchEvent(new Event("close"));
  };
});

afterEach(() => vi.unstubAllGlobals());

const suggestion: Schemas["ProfileSuggestion"] = {
  profile: {
    name: "sugerido",
    cpu_quota_percent: 300,
    memory_max_bytes: 4 * 1024 ** 3,
    io_read_bytes_per_sec: 0,
    io_weight: 50,
    workers: 3,
    clamd_concurrency: 3,
    max_runtime_sec: 43200,
    nice: 10,
    max_file_bytes: 0,
    pressure_cpu: 50,
    pressure_io: 40,
    pressure_memory: 20,
  },
  reasons: [
    { code: "cpu_normal", values: { cpus: 8, quota: 300, share: 50, pressure: 6.25, load_per_core: 0.456 } },
    { code: "memory_normal", values: { total: 16 * 1024 ** 3, max: 4 * 1024 ** 3, percent: 40, pressure: 0 } },
    { code: "disk_hdd", values: { workers: 2, io_weight: 25, io_read: 50 << 20 } },
  ],
  basis: {
    cpus: 8,
    memory_bytes: 16 * 1024 ** 3,
    disk_type: "ssd",
    psi: true,
    cpu_pressure: 6.25,
    io_pressure: 1,
    memory_pressure: 0,
    load_avg: 3.65,
    history_runs: 2,
    limited_ratio: 0.125,
  },
};

describe("explicação da sugestão", () => {
  it("formata bytes, carga e porcentagens no idioma ativo", () => {
    const [cpu, memory, disk] = suggestion.reasons.map((r) => reasonText(r, t, "pt-BR"));
    expect(cpu).toBe(
      "Ocupação moderada (carga de 0,46 por núcleo): metade dos 8 núcleos, até 300% de CPU, com um núcleo livre para o sistema.",
    );
    expect(memory).toBe("Memória máxima de 4 GiB: 40% de 16 GiB, no máximo 4 GiB.");
    expect(disk).toContain("leitura limitada a 50 MiB/s");
  });

  it("código desconhecido vira linha genérica", () => {
    const r = { code: "novo_criterio", values: {} } as unknown as Schemas["SuggestionReason"];
    expect(reasonText(r, t, "pt-BR")).toBe("Critério novo_criterio (versão mais nova do servidor).");
  });

  it("aplicar grava o perfil próprio com o nome sugerido", () => {
    expect(suggestedProfileBody({ ...suggestion, profile: { ...suggestion.profile, name: "x" } }).name).toBe("sugerido");
  });

  it("limiares de pressão e tipo de disco", () => {
    expect(pressureParts({ pressure_cpu: 60, pressure_io: 0 })).toEqual([{ resource: "cpu", value: 60 }]);
    expect(pressureParts({})).toEqual([]);
    expect(diskKey({ disk_type: "nvme", rotational: false })).toBe("config.resources.diskNvme");
    expect(diskKey({ rotational: true })).toBe("config.resources.diskRotational");
  });
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function renderPanel(isAdmin: boolean, onApplied = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <SuggestionPanel isAdmin={isAdmin} hasSuggested={false} onApplied={onApplied} />
    </QueryClientProvider>,
  );
  return onApplied;
}

describe("SuggestionPanel", () => {
  it("mostra limites e explicação; leitor não aplica", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (req: Request) => (req.url.endsWith("/api/v1/resources/suggestion") ? json(suggestion) : json({ error: "x" }, 401))),
    );
    renderPanel(false);
    expect(await screen.findByText(/metade dos 8 núcleos/)).toBeInTheDocument();
    expect(screen.getByText(/2 execuções recentes consideradas, 12,5% do tempo limitadas/)).toBeInTheDocument();
    expect(screen.getByText("CPU 50% · E/S 40% · memória 20%")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Aplicar sugestão" })).toBeNull();
    expect(screen.getByText("Só administradores aplicam a sugestão.")).toBeInTheDocument();
  });

  it("administrador aplica com reautenticação e grava o perfil sugerido", async () => {
    const user = userEvent.setup();
    const calls: { method: string; url: string; body?: unknown }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (req: Request) => {
        const body = req.method === "GET" ? undefined : await req.json().catch(() => undefined);
        calls.push({ method: req.method, url: new URL(req.url).pathname, body });
        if (req.url.endsWith("/api/v1/resources/suggestion")) return json(suggestion);
        if (req.url.endsWith("/api/v1/auth/session")) return json({ error: "x" }, 401);
        if (req.url.endsWith("/api/v1/auth/reauth")) return json({ authenticated: true, setup_required: false, secure_transport: true });
        if (req.method === "PUT") return json({ profiles: [] });
        return json({ error: "inesperado" }, 500);
      }),
    );
    const onApplied = renderPanel(true);
    await user.click(await screen.findByRole("button", { name: "Aplicar sugestão" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Confirme sua senha"), "senha-muito-longa");
    await user.click(within(dialog).getByRole("button", { name: "Aplicar sugestão" }));
    await vi.waitFor(() => expect(onApplied).toHaveBeenCalledWith("sugerido"));
    expect(calls.find((c) => c.url.endsWith("/auth/reauth"))?.body).toEqual({ password: "senha-muito-longa" });
    expect(calls.find((c) => c.method === "PUT")).toEqual({
      method: "PUT",
      url: "/api/v1/resources/profiles/sugerido",
      body: suggestion.profile,
    });
  });
});
