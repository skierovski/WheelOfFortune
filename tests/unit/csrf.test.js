import { describe, expect, it, vi } from "vitest";

vi.mock("../../src/utils/env.js", () => ({
  env: { NODE_ENV: "production", PUBLIC_BASE_URL: "https://wheel.example" },
}));

const { csrfProtection } = await import("../../src/middleware/csrf.js");

function run({ method = "POST", path = "/dashboard/config", origin, fetchSite } = {}) {
  const headers = { origin, "sec-fetch-site": fetchSite };
  const req = {
    method,
    path,
    protocol: "https",
    get: (name) => headers[name.toLowerCase()] || (name.toLowerCase() === "host" ? "wheel.example" : undefined),
  };
  const result = { next: false, status: null, body: null };
  const res = {
    status(code) { result.status = code; return this; },
    json(body) { result.body = body; return this; },
  };
  csrfProtection(req, res, () => { result.next = true; });
  return result;
}

describe("csrfProtection", () => {
  it("allows same-origin mutations", () => {
    expect(run({ origin: "https://wheel.example", fetchSite: "same-origin" }).next).toBe(true);
  });

  it("rejects cross-site mutations", () => {
    expect(run({ origin: "https://evil.example", fetchSite: "cross-site" }).status).toBe(403);
  });

  it("rejects production mutations without browser origin metadata", () => {
    expect(run().status).toBe(403);
  });

  it("does not block safe methods or public webhook routes", () => {
    expect(run({ method: "GET" }).next).toBe(true);
    expect(run({ path: "/webhook" }).next).toBe(true);
  });
});
