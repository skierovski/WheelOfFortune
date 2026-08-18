import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openDatabase } from "../../src/db.js";

describe("persistent OAuth transactions", () => {
  let db;
  beforeEach(() => { db = openDatabase(":memory:"); });
  afterEach(() => db.close());

  it("atomically consumes a transaction once", () => {
    db.storeOAuthTransaction({
      state_hash: "state-hash",
      code_verifier: "verifier",
      redirect_uri: "https://app.example/auth/callback",
      return_path: "/dashboard",
      binding_hash: "binding-hash",
      created_at: 1_000,
      expires_at: 2_000,
    });
    expect(db.consumeOAuthTransaction("state-hash", 1_500)?.code_verifier).toBe("verifier");
    expect(db.consumeOAuthTransaction("state-hash", 1_501)).toBeNull();
  });

  it("prunes expired transactions before lookup", () => {
    db.storeOAuthTransaction({
      state_hash: "expired",
      code_verifier: "verifier",
      redirect_uri: "https://app.example/auth/callback",
      return_path: "/",
      binding_hash: "binding-hash",
      created_at: 1_000,
      expires_at: 1_100,
    });
    expect(db.consumeOAuthTransaction("expired", 1_101)).toBeNull();
    expect(db.raw.prepare("SELECT COUNT(*) AS count FROM oauth_transactions").get().count).toBe(0);
  });
});
