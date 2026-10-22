import type { Schemas } from "../../api/client";
import { bytesToMiB, mibToBytes } from "./units";

// Perfis de recursos: conversão entre o contrato (bytes, segundos) e o formulário (MiB, minutos).

export type ResourceProfile = Schemas["ResourceProfile"];
export type ProfileEntry = Schemas["ProfileEntry"];

export const PROFILE_NAME = /^[a-z0-9][a-z0-9-]{0,31}$/;

export type ProfileFormValues = {
  name: string;
  cpuPercent: string;
  memoryMiB: string;
  ioReadMiBps: string;
  ioWeight: string;
  workers: string;
  clamdConcurrency: string;
  maxRuntimeMin: string;
  nice: string;
  maxFileMiB: string;
  pressureCpu: string;
  pressureIo: string;
  pressureMemory: string;
};

export function valuesFromProfile(p: ResourceProfile): ProfileFormValues {
  return {
    name: p.name,
    cpuPercent: String(p.cpu_quota_percent),
    memoryMiB: String(bytesToMiB(p.memory_max_bytes)),
    ioReadMiBps: String(bytesToMiB(p.io_read_bytes_per_sec)),
    ioWeight: String(p.io_weight),
    workers: String(p.workers),
    clamdConcurrency: String(p.clamd_concurrency),
    maxRuntimeMin: String(Math.round(p.max_runtime_sec / 60)),
    nice: String(p.nice),
    maxFileMiB: String(bytesToMiB(p.max_file_bytes)),
    pressureCpu: String(p.pressure_cpu ?? 0),
    pressureIo: String(p.pressure_io ?? 0),
    pressureMemory: String(p.pressure_memory ?? 0),
  };
}

/** Ponto de partida de um perfil novo: cópia do perfil padrão, sem o nome. */
export function newProfileValues(base: ResourceProfile | undefined): ProfileFormValues {
  const values = base
    ? valuesFromProfile(base)
    : {
        name: "",
        cpuPercent: "100",
        memoryMiB: "1024",
        ioReadMiBps: "0",
        ioWeight: "50",
        workers: "1",
        clamdConcurrency: "1",
        maxRuntimeMin: "720",
        nice: "10",
        maxFileMiB: "0",
        pressureCpu: "60",
        pressureIo: "40",
        pressureMemory: "20",
      };
  return { ...values, name: "" };
}

export type ProfileBuild = { ok: true; body: ResourceProfile } | { ok: false; field: keyof ProfileFormValues };

function whole(text: string): number | null {
  const t = text.trim().replace(",", ".");
  if (!/^\d+(\.\d+)?$/.test(t)) return null;
  return Number(t);
}

/**
 * Corpo de PUT /api/v1/resources/profiles/{name}. Só confere se cada campo é número não negativo; os limites
 * (reserva de CPU e de memória, faixas) são do servidor, que recusa com a mensagem explicando o motivo.
 */
export function buildProfileBody(v: ProfileFormValues): ProfileBuild {
  const fields: (keyof ProfileFormValues)[] = [
    "cpuPercent",
    "memoryMiB",
    "ioReadMiBps",
    "ioWeight",
    "workers",
    "clamdConcurrency",
    "maxRuntimeMin",
    "nice",
    "maxFileMiB",
    "pressureCpu",
    "pressureIo",
    "pressureMemory",
  ];
  const n: Partial<Record<keyof ProfileFormValues, number>> = {};
  for (const f of fields) {
    const value = whole(v[f]);
    if (value === null) return { ok: false, field: f };
    n[f] = value;
  }
  const num = (f: keyof ProfileFormValues) => n[f] ?? 0;
  return {
    ok: true,
    body: {
      name: v.name.trim(),
      cpu_quota_percent: Math.round(num("cpuPercent")),
      memory_max_bytes: mibToBytes(num("memoryMiB")),
      io_read_bytes_per_sec: mibToBytes(num("ioReadMiBps")),
      io_weight: Math.round(num("ioWeight")),
      workers: Math.round(num("workers")),
      clamd_concurrency: Math.round(num("clamdConcurrency")),
      max_runtime_sec: Math.round(num("maxRuntimeMin") * 60),
      nice: Math.round(num("nice")),
      max_file_bytes: mibToBytes(num("maxFileMiB")),
      pressure_cpu: Math.round(num("pressureCpu")),
      pressure_io: Math.round(num("pressureIo")),
      pressure_memory: Math.round(num("pressureMemory")),
    },
  };
}

export type PressureLimits = Pick<ResourceProfile, "pressure_cpu" | "pressure_io" | "pressure_memory">;

/** Limiares de pressão ligados, na ordem CPU, E/S, memória (zero ou ausente = desligado). */
export function pressureParts(p: PressureLimits): { resource: "cpu" | "io" | "memory"; value: number }[] {
  const parts: { resource: "cpu" | "io" | "memory"; value: number }[] = [];
  if (p.pressure_cpu) parts.push({ resource: "cpu", value: p.pressure_cpu });
  if (p.pressure_io) parts.push({ resource: "io", value: p.pressure_io });
  if (p.pressure_memory) parts.push({ resource: "memory", value: p.pressure_memory });
  return parts;
}
