import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock env before importing cookies module
vi.mock("../../src/utils/env.js", () => ({
  env: {
    SESSION_SECRET: "test-secret-key-for-unit-tests",
    NODE_ENV: "development",
  },
}));

const { parseCookies, hmacHex, setSessionCookie, getSessionBroadcasterId } =
  await import("../../src/utils/cookies.js");

describe("parseCookies", () => {
  it("parses a single cookie", () => {
    const req = { headers: { cookie: "foo=bar" } };
    expect(parseCookies(req)).toEqual({ foo: "bar" });
  });

  it("parses multiple cookies", () => {
    const req = { headers: { cookie: "a=1; b=2; c=3" } };
    expect(parseCookies(req)).toEqual({ a: "1", b: "2", c: "3" });
  });

  it("decodes URL-encoded values", () => {
    const req = { headers: { cookie: "name=hello%20world" } };
    expect(parseCookies(req)).toEqual({ name: "hello world" });
  });

  it("returns empty object when no cookie header", () => {
    expect(parseCookies({ headers: {} })).toEqual({});
  });

  it("handles empty cookie header", () => {
    expect(parseCookies({ headers: { cookie: "" } })).toEqual({});
  });

  it("handles cookies with = in value", () => {
    const req = { headers: { cookie: "token=abc=def=ghi" } };
    expect(parseCookies(req)).toEqual({ token: "abc=def=ghi" });
  });
});

describe("hmacHex", () => {
  it("returns a hex string", () => {
    const result = hmacHex("test");
    expect(result).toMatch(/^[0-9a-f]+$/);
  });

  it("is deterministic for the same input", () => {
    expect(hmacHex("12345")).toBe(hmacHex("12345"));
  });

  it("returns different results for different inputs", () => {
    expect(hmacHex("12345")).not.toBe(hmacHex("54321"));
  });

  it("returns a 64-char hex (SHA-256 output)", () => {
    expect(hmacHex("anything")).toHaveLength(64);
  });
});

describe("setSessionCookie", () => {
  it("sets a signed cookie on the response", () => {
    let cookieHeader = null;
    const res = {
      setHeader: (name, value) => {
        if (name === "Set-Cookie") cookieHeader = value;
      },
    };
    setSessionCookie(res, 12345);

    expect(cookieHeader).toBeTruthy();
    expect(cookieHeader).toContain("wheel_sess=");
    expect(cookieHeader).toContain("Path=/");
    expect(cookieHeader).toContain("HttpOnly");
    expect(cookieHeader).toContain("SameSite=Lax");
    expect(cookieHeader).toContain("Max-Age=2592000");
  });

  it("does not include Secure flag in development", () => {
    let cookieHeader = null;
    const res = {
      setHeader: (name, value) => {
        if (name === "Set-Cookie") cookieHeader = value;
      },
    };
    setSessionCookie(res, 12345);
    expect(cookieHeader).not.toContain("Secure");
  });

  it("stores an opaque token without embedding a broadcaster id", () => {
    let cookieHeader = null;
    const res = {
      setHeader: (name, value) => {
        if (name === "Set-Cookie") cookieHeader = value;
      },
    };
    setSessionCookie(res, "opaque-random-token");

    // Extract the cookie value
    const match = cookieHeader.match(/wheel_sess=([^;]+)/);
    expect(match).toBeTruthy();
    const decoded = decodeURIComponent(match[1]);
    expect(decoded).toBe("opaque-random-token");
    expect(decoded).not.toContain("99999");
  });
});

describe("getSessionBroadcasterId", () => {
  function makeReq(token, broadcasterId = 12345) {
    return {
      headers: { cookie: `wheel_sess=${encodeURIComponent(token)}` },
      app: { locals: { db: { getSession: () => ({ broadcaster_id: broadcasterId }) } } },
    };
  }

  it("resolves broadcaster id from the server-side session", () => {
    expect(getSessionBroadcasterId(makeReq("opaque-token", 12345))).toBe(12345);
  });

  it("returns null when no cookie", () => {
    expect(getSessionBroadcasterId({ headers: {} })).toBeNull();
  });

  it("returns null when cookie is missing wheel_sess", () => {
    expect(
      getSessionBroadcasterId({ headers: { cookie: "other=value" } })
    ).toBeNull();
  });

  it("returns null when session token is unknown", () => {
    const req = {
      headers: { cookie: "wheel_sess=unknown" },
      app: { locals: { db: { getSession: () => null } } },
    };
    expect(getSessionBroadcasterId(req)).toBeNull();
  });

  it("returns null when the session database is unavailable", () => {
    const req = {
      headers: { cookie: "wheel_sess=opaque" },
    };
    expect(getSessionBroadcasterId(req)).toBeNull();
  });

  it("returns null when cookie has no dot separator", () => {
    const req = { headers: { cookie: "wheel_sess=nodot" } };
    expect(getSessionBroadcasterId(req)).toBeNull();
  });

  it("round-trips an opaque cookie through a server-side lookup", () => {
    let cookieHeader = null;
    const res = {
      setHeader: (name, value) => {
        if (name === "Set-Cookie") cookieHeader = value;
      },
    };
    setSessionCookie(res, "random-session-token");

    // Extract Set-Cookie value and use it as a request cookie
    const match = cookieHeader.match(/wheel_sess=([^;]+)/);
    const req = {
      headers: { cookie: `wheel_sess=${match[1]}` },
      app: { locals: { db: { getSession: () => ({ broadcaster_id: 42 }) } } },
    };
    expect(getSessionBroadcasterId(req)).toBe(42);
  });
});
