import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Schemas } from "../../api/client";
import { AdjustLimitsForm } from "./AdjustLimitsForm";
import { adjustValuesFrom, buildAdjustBody, phaseShares, throttleOutcome } from "./performance";
import { ComparisonPanel, PerformancePanel, ThrottleNote } from "./RunPerformance";
import type { Run } from "./runFormat";

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

const MIB = 1 << 20;
const profile: Schemas["ResourceProfile"] = {
  name: "padrao",
  cpu_quota_percent: 200,
  memory_max_bytes: 2048 * MIB,
  io_read_bytes_per_sec: 0,
  io_weight: 50,
  workers: 2,
  clamd_concurrency: 2,
  max_runtime_sec: 43200,
  nice: 10,
  max_file_bytes: 0,
  pressure_cpu: 60,
  pressure_io: 40,
  pressure_memory: 20,
};

const metrics: Schemas["RunMetrics"] = {
  phases: [
    { phase: "selftest", seconds: 5 },
    { phase: "scanning", seconds: 90 },
    { phase: "large_files", seconds: 5 },
  ],
  cpu_seconds: 125,
  cpu_seconds_per_gb: 12.5,
  memory_peak_bytes: 300 * MIB,
  bytes_read: 10 * 1024 * MIB,
  source: "cgroup",
  throttle: {
    available: true,
    enabled: true,
    limited_seconds: 42,
    paused_seconds: 12,
    events: [
      { at: "2026-10-22T03:00:00Z", action: "reduce", resource: "io", pressure: 45.5, threshold: 40, workers: 1 },
      { at: "2026-10-22T03:00:30Z", action: "restore", resource: "io", pressure: 3, threshold: 40, workers: 2 },
    ],
    events_dropped: 0,
  },
};

function run(over: Partial<Run> = {}): Run {
  return {
    id: "20261022-030000-abcd1234",
    kind: "files",
    status: "completed",
    origin: "manual",
    requested_by: "ana",
    paths: ["/home"],
    exclude: [],
    incremental: true,
    profile,
    priority: 0,
    attempts: 1,
    created_at: "2026-10-22T03:00:00Z",
    started_at: "2026-10-22T03:00:00Z",
    finished_at: "2026-10-22T03:01:40Z",
    phase: "done",
    paused: false,
    files_seen: 1000,
    files_eligible: 1000,
    files_processed: 1000,
    bytes_eligible: 10 * 1024 * MIB,
    bytes_processed: 10 * 1024 * MIB,
    findings_count: 0,
    error: "",
    summary: {
      status: "completed",
      files_seen: 1000,
      files_eligible: 1000,
      bytes_eligible: 10 * 1024 * MIB,
      findings: 0,
      objects: 900,
      cache_hits: 100,
      files_per_second: 10,
      mb_per_second: 102.4,
      metrics,
    },
    ...over,
  };
}

function wrap(children: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("ajuste em tempo real", () => {
  it("envia só o que mudou, em bytes", () => {
    const values = adjustValuesFrom(profile);
    expect(values).toEqual({ cpuPercent: "200", memoryMiB: "2048", ioReadMiBps: "0", ioWeight: "50" });
    expect(buildAdjustBody({ ...values, cpuPercent: "100", ioReadMiBps: "20" }, profile)).toEqual({
      ok: true,
      body: { cpu_quota_percent: 100, io_read_bytes_per_sec: 20 * MIB },
      changes: ["cpuPercent", "ioReadMiBps"],
    });
    expect(buildAdjustBody({ ...values, memoryMiB: "1024" }, profile, true)).toEqual({
      ok: true,
      body: { memory_max_bytes: 1024 * MIB, no_reserve: true },
      changes: ["memoryMiB"],
    });
  });

  it("recusa número inválido e ajuste sem mudança", () => {
    const values = adjustValuesFrom(profile);
    expect(buildAdjustBody({ ...values, cpuPercent: "1,5" }, profile)).toEqual({ ok: false, field: "cpuPercent", code: "notNumber" });
    expect(buildAdjustBody({ ...values, ioWeight: "-1" }, profile)).toEqual({ ok: false, field: "ioWeight", code: "notNumber" });
    expect(buildAdjustBody(values, profile)).toEqual({ ok: false, code: "nothing" });
  });

  it("administrador confirma com a senha e o formulário mostra a recusa das travas", async () => {
    const user = userEvent.setup();
    const posts: unknown[] = [];
    let refuse = true;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (req: Request) => {
        if (req.url.endsWith("/api/v1/auth/session")) return json({ error: "x" }, 401);
        if (req.url.endsWith("/api/v1/auth/reauth")) return json({ authenticated: true, setup_required: false, secure_transport: true });
        if (req.url.endsWith("/adjust")) {
          posts.push(await req.json());
          if (refuse) return json({ error: "executor: limite recusado: CPU acima da reserva do sistema", code: "limit_refused" }, 400);
          return json(run({ status: "running", profile: { ...profile, cpu_quota_percent: 100 } }));
        }
        return json({ error: "inesperado" }, 500);
      }),
    );
    const onDone = vi.fn();
    wrap(<AdjustLimitsForm run={run({ status: "running" })} allowNoReserve={false} onDone={onDone} />);
    expect(screen.queryByLabelText("Pedir limites acima da reserva do sistema")).toBeNull();

    await user.click(screen.getByRole("button", { name: "Ajustar limites" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Nenhum valor mudou");

    const cpu = screen.getByLabelText("CPU (%)");
    await user.clear(cpu);
    await user.type(cpu, "800");
    await user.click(screen.getByRole("button", { name: "Ajustar limites" }));
    let dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("CPU (%): 800")).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText("Confirme sua senha"), "senha-muito-longa");
    await user.click(within(dialog).getByRole("button", { name: "Ajustar limites" }));
    expect(await screen.findByText(/O ajuste foi recusado: executor: limite recusado/)).toBeInTheDocument();
    expect(onDone).not.toHaveBeenCalled();

    refuse = false;
    await user.clear(cpu);
    await user.type(cpu, "100");
    await user.click(screen.getByRole("button", { name: "Ajustar limites" }));
    dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Confirme sua senha"), "senha-muito-longa");
    await user.click(within(dialog).getByRole("button", { name: "Ajustar limites" }));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalledWith("Limites ajustados."));
    expect(posts).toEqual([{ cpu_quota_percent: 800 }, { cpu_quota_percent: 100 }]);
  });
});

describe("métricas de desempenho", () => {
  it("parcela por etapa e situação da limitação", () => {
    expect(phaseShares(metrics.phases).map((p) => p.share)).toEqual([0.05, 0.9, 0.05]);
    expect(throttleOutcome(metrics)).toBe("limited");
    expect(throttleOutcome({ ...metrics, throttle: { ...metrics.throttle, enabled: false } })).toBe("off");
    expect(throttleOutcome({ ...metrics, throttle: { ...metrics.throttle, available: false } })).toBe("unavailable");
    expect(throttleOutcome({ ...metrics, throttle: { ...metrics.throttle, events: [], limited_seconds: 0 } })).toBe("none");
  });

  it("mostra vazão, CPU, memória, etapas e eventos de pressão", () => {
    wrap(<PerformancePanel run={run()} />);
    expect(screen.getByText("Arquivos por segundo").nextSibling).toHaveTextContent("10");
    expect(screen.getByText("Leitura por segundo").nextSibling).toHaveTextContent("102,4 MiB/s");
    expect(screen.getByText("CPU consumida").nextSibling).toHaveTextContent("2 min 5 s");
    expect(screen.getByText("Pico de memória").nextSibling).toHaveTextContent("300 MiB");
    expect(screen.getByText("Tempo limitado por pressão").nextSibling).toHaveTextContent("42 s (pausada 12 s)");
    const phases = screen.getByRole("table", { name: "Duração de cada etapa da execução e parcela do total" });
    expect(within(phases).getByText("Análise dos arquivos")).toBeInTheDocument();
    expect(within(phases).getByText("90%")).toBeInTheDocument();
    const events = screen.getByRole("table", { name: "Mudanças de ritmo por pressão durante a execução" });
    expect(within(events).getByText("Reduziu o ritmo")).toBeInTheDocument();
    expect(within(events).getByText("45,5%")).toBeInTheDocument();
  });

  it("explica quando não há medidas ou limitação", () => {
    const failed = run({ status: "failed" });
    delete failed.summary;
    wrap(<PerformancePanel run={failed} />);
    expect(screen.getByText(/Sem medidas de desempenho/)).toBeInTheDocument();
  });

  it("avisa a limitação em andamento", () => {
    wrap(
      <>
        <ThrottleNote run={run({ status: "running", throttle: { state: "reduced", workers: 1, resource: "io", pressure: 55 } })} />
        <ThrottleNote run={run({ status: "running", throttle: { state: "paused", workers: 0, resource: "cpu", pressure: 95 } })} />
      </>,
    );
    const notes = screen.getAllByRole("status");
    expect(notes[0]).toHaveTextContent("Ritmo reduzido pela pressão de E/S do servidor (55%): 1 leitura em paralelo agora.");
    expect(notes[1]).toHaveTextContent("Lotes suspensos pela pressão de CPU do servidor (95%)");
  });
});

describe("comparativo", () => {
  it("lista a execução atual e as anteriores, com link para as outras", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        json({
          kind: "files",
          runs: [
            { id: "atual", status: "completed", profile: "padrao", created_at: "2026-10-22T03:00:00Z", duration_seconds: 100, files_eligible: 1000, bytes_eligible: 1, files_per_second: 10, mb_per_second: 50, cache_hits: 0, findings: 2, current: true, cpu_seconds: 125, memory_peak_bytes: 300 * MIB, limited_seconds: 42 },
            { id: "anterior", status: "partial", profile: "leve", created_at: "2026-10-21T03:00:00Z", duration_seconds: 300, files_eligible: 1000, bytes_eligible: 1, files_per_second: 3.3, mb_per_second: 12, cache_hits: 0, findings: 0, current: false },
          ],
        }),
      ),
    );
    wrap(<ComparisonPanel run={run({ id: "atual" })} />);
    const table = await screen.findByRole("table", { name: "Desempenho desta execução e das últimas do mesmo tipo" });
    const [, current, previous] = within(table).getAllByRole("row");
    if (!current || !previous) throw new Error("linhas do comparativo ausentes");
    expect(current).toHaveAttribute("aria-current", "true");
    expect(within(current).getByText("Esta")).toBeInTheDocument();
    expect(within(previous).getByRole("link", { name: "anterior" })).toHaveAttribute("href", "/execucoes/anterior");
    expect(within(previous).getByText("Leve")).toBeInTheDocument();
  });

  it("explica quando ainda não há com o que comparar", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ kind: "files", runs: [{ id: "atual", status: "running", profile: "padrao", created_at: "2026-10-22T03:00:00Z", duration_seconds: 0, files_eligible: 0, bytes_eligible: 0, files_per_second: 0, mb_per_second: 0, cache_hits: 0, findings: 0, current: true }] })));
    wrap(<ComparisonPanel run={run({ id: "atual", status: "running" })} />);
    expect(await screen.findByText("Ainda não há outras execuções terminadas deste tipo para comparar.")).toBeInTheDocument();
  });
});
