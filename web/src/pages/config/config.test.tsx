import i18n from "i18next";
import { describe, expect, it } from "vitest";
import { cronToText } from "./cronText";
import { engineGuidance } from "./EnginesPage";
import { zoneProp } from "./queries";
import { buildProfileBody, valuesFromProfile, type ResourceProfile } from "./resources";
import { fieldForServerError } from "./scheduleErrors";
import { buildScheduleInput, describeCron, emptyScheduleValues, splitLines } from "./schedules";
import { formatBytes, splitDuration } from "./units";

const t = i18n.t.bind(i18n);

describe("expressão cron em linguagem simples", () => {
  it("reconhece as formas comuns", () => {
    expect(describeCron("0 3 * * *")).toEqual({ key: "dailyAt", hour: 3, minute: 0 });
    expect(describeCron("@daily")).toEqual({ key: "dailyAt", hour: 0, minute: 0 });
    expect(describeCron("*/15 * * * *")).toEqual({ key: "everyMinutes", n: 15 });
    expect(describeCron("5 * * * *")).toEqual({ key: "hourlyAt", minute: 5 });
    expect(describeCron("0 */6 * * *")).toEqual({ key: "everyHours", n: 6, minute: 0 });
    expect(describeCron("30 2 * * 1-5")).toEqual({ key: "weeklyAt", days: [1, 2, 3, 4, 5], hour: 2, minute: 30 });
    expect(describeCron("0 4 * * SAT,sun")).toEqual({ key: "weeklyAt", days: [0, 6], hour: 4, minute: 0 });
    expect(describeCron("0 4 * * 5-7")).toEqual({ key: "weeklyAt", days: [0, 5, 6], hour: 4, minute: 0 });
    expect(describeCron("0 1 15 * *")).toEqual({ key: "monthlyAt", day: 15, hour: 1, minute: 0 });
    expect(describeCron("@every 90m")).toEqual({ key: "every", duration: "90m" });
  });

  it("devolve null para formas não cobertas ou inválidas", () => {
    expect(describeCron("")).toBeNull();
    expect(describeCron("0 3 * *")).toBeNull();
    expect(describeCron("0 3 1-7 * 1")).toBeNull();
    expect(describeCron("61 3 * * *")).toBeNull();
    expect(describeCron("@reboot")).toBeNull();
  });

  it("escreve o texto no idioma ativo", () => {
    expect(cronToText("0 3 * * *", t, "pt-BR")).toBe("Todo dia às 03:00");
    expect(cronToText("*/10 * * * *", t, "pt-BR")).toBe("A cada 10 minutos");
    expect(cronToText("0 3 * * 1,3", t, "pt-BR")).toBe("Toda semana (segunda-feira e quarta-feira) às 03:00");
    expect(cronToText("0 3 1-7 * 1", t, "pt-BR")).toBe("Expressão personalizada: confira as próximas execuções");
  });
});

describe("corpo do agendamento", () => {
  it("varredura de arquivos leva caminhos limpos", () => {
    const body = buildScheduleInput({
      ...emptyScheduleValues("America/Sao_Paulo"),
      name: "  Diária  ",
      cron: " 0 3 * * * ",
      paths: "/home\n\n  /var/www  \r\n",
      exclude: "",
      incremental: false,
    });
    expect(body).toEqual({
      name: "Diária",
      kind: "files",
      cron: "0 3 * * *",
      timezone: "America/Sao_Paulo",
      profile: "padrao",
      missed_policy: "run_once",
      enabled: true,
      incremental: false,
      paths: ["/home", "/var/www"],
      exclude: [],
    });
  });

  it("inspeção de processos não envia caminhos", () => {
    const body = buildScheduleInput({ ...emptyScheduleValues(""), name: "Processos", kind: "processes", paths: "/home" });
    expect(body).not.toHaveProperty("paths");
    expect(body).not.toHaveProperty("exclude");
    expect(body.timezone).toBe("UTC");
  });

  it("separa linhas e liga a mensagem do servidor ao campo", () => {
    expect(splitLines(" a \n\nb")).toEqual(["a", "b"]);
    expect(fieldForServerError("fuso horário inválido: Marte/Base")).toBe("timezone");
    expect(fieldForServerError("expressão cron inválida: expected 5 fields")).toBe("cron");
    expect(fieldForServerError("informe um nome para o agendamento")).toBe("name");
    expect(fieldForServerError("informe ao menos um caminho para a varredura de arquivos")).toBe("paths");
    expect(fieldForServerError("política de horário perdido inválida")).toBe("missedPolicy");
    expect(fieldForServerError("erro inesperado")).toBeNull();
  });

  it("ignora fuso que o navegador não reconhece", () => {
    expect(zoneProp("America/Sao_Paulo")).toEqual({ timeZone: "America/Sao_Paulo" });
    expect(zoneProp("Marte/Base")).toEqual({});
    expect(zoneProp(undefined)).toEqual({});
  });
});

describe("perfil de recursos", () => {
  const profile: ResourceProfile = {
    name: "madrugada",
    cpu_quota_percent: 150,
    memory_max_bytes: 2 * 1024 ** 3,
    io_read_bytes_per_sec: 0,
    io_weight: 50,
    workers: 2,
    clamd_concurrency: 2,
    max_runtime_sec: 12 * 3600,
    nice: 10,
    max_file_bytes: 0,
    pressure_cpu: 60,
    pressure_io: 40,
    pressure_memory: 0,
  };

  it("converte ida e volta entre bytes/segundos e MiB/minutos", () => {
    const values = valuesFromProfile(profile);
    expect(values.memoryMiB).toBe("2048");
    expect(values.maxRuntimeMin).toBe("720");
    expect(buildProfileBody(values)).toEqual({ ok: true, body: profile });
  });

  it("aponta o campo que não é número", () => {
    expect(buildProfileBody({ ...valuesFromProfile(profile), workers: "dois" })).toEqual({ ok: false, field: "workers" });
    expect(buildProfileBody({ ...valuesFromProfile(profile), nice: "-1" })).toEqual({ ok: false, field: "nice" });
    expect(buildProfileBody({ ...valuesFromProfile(profile), pressureIo: "alto" })).toEqual({ ok: false, field: "pressureIo" });
  });

  it("formata tamanhos e durações", () => {
    expect(formatBytes(0, "pt-BR")).toBe("0 B");
    expect(formatBytes(1536 << 20, "pt-BR")).toBe("1,5 GiB");
    expect(formatBytes(512 << 20, "en")).toBe("512 MiB");
    expect(splitDuration(45000)).toEqual({ hours: 12, minutes: 30 });
  });
});

describe("orientação dos motores", () => {
  it("usa só o que a API informa", () => {
    expect(engineGuidance({ id: "clamav", name: "ClamAV", state: "operational" }, undefined)).toBeNull();
    expect(engineGuidance({ id: "clamav", name: "ClamAV", state: "degraded", mode: "clamscan" }, undefined)).toBe("clamdFallback");
    expect(engineGuidance({ id: "yara-x", name: "YARA-X", state: "unavailable" }, undefined)).toBe("yaraMissing");
    expect(
      engineGuidance(
        { id: "yara-x", name: "YARA-X", state: "degraded", last_selftest: { run_id: "r1", passed: false, detail: "x" } },
        undefined,
      ),
    ).toBe("selftestFailed");
    expect(engineGuidance({ id: "clamav", name: "ClamAV", state: "unavailable" }, "executor indisponível")).toBe("executorDown");
  });
});
