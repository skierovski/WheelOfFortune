import { describe, expect, it, vi } from "vitest";

vi.mock("../../src/utils/env.js", () => ({
  env: { NODE_ENV: "production", PUBLIC_BASE_URL: "https://wheel.example" },
}));
vi.mock("../../src/db.js", () => ({ getDb: vi.fn() }));
vi.mock("../../src/services/spins.js", () => ({ spins: {} }));
vi.mock("../../src/services/slots.js", () => ({ slots: {} }));

const { isAllowedWebSocketOrigin } = await import("../../src/ws.js");

describe("WebSocket origin", () => {
  it("accepts the configured public origin", () => {
    expect(isAllowedWebSocketOrigin({ headers: { origin: "https://wheel.example" } })).toBe(true);
  });

  it("rejects foreign and missing origins in production", () => {
    expect(isAllowedWebSocketOrigin({ headers: { origin: "https://evil.example" } })).toBe(false);
    expect(isAllowedWebSocketOrigin({ headers: {} })).toBe(false);
  });
});
