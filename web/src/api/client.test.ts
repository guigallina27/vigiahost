import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, fetchHealth, type Health } from "./client";

const degraded: Health = { status: "degraded", version: "0.1.0", executor: { connected: false, error: "connection refused" } };

function mockFetch(response: Response | Error) {
  vi.stubGlobal(
    "fetch",
    vi.fn(() => (response instanceof Error ? Promise.reject(response) : Promise.resolve(response))),
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("fetchHealth", () => {
  it("trata 503 com corpo do contrato como estado degradado, não como erro", async () => {
    mockFetch(new Response(JSON.stringify(degraded), { status: 503, headers: { "Content-Type": "application/json" } }));
    await expect(fetchHealth()).resolves.toEqual(degraded);
  });

  it("transforma falha de rede em ApiError com a causa", async () => {
    mockFetch(new TypeError("Failed to fetch"));
    await expect(fetchHealth()).rejects.toThrow(ApiError);
  });

  it("trata outros status como erro", async () => {
    mockFetch(new Response("erro interno", { status: 500 }));
    await expect(fetchHealth()).rejects.toMatchObject({ status: 500 });
  });
});
