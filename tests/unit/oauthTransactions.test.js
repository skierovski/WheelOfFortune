import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  consumeOAuthTransaction,
  storeOAuthTransaction,
} from "../../src/services/oauthTransactions.js";
import { openDatabase } from "../../src/db.js";

describe("OAuth transactions", () => {
  let db;
  beforeEach(() => { db = openDatabase(":memory:"); });
  afterEach(() => db.close());

  it("is bound to the browser and single-use", () => {
    const tx = storeOAuthTransaction({
      state: "state-1",
      codeVerifier: "verifier",
      redirectUri: "https://app.example/auth/callback",
      returnPath: "/dashboard",
    }, 1_000, undefined, db);

    expect(consumeOAuthTransaction("state-1", "wrong", 1_001, db)).toBeNull();
    expect(consumeOAuthTransaction("state-1", tx.browserBinding, 1_002, db)).toBeNull();
  });

  it("returns and consumes a valid transaction", () => {
    const tx = storeOAuthTransaction({
      state: "state-2",
      codeVerifier: "verifier",
      redirectUri: "https://app.example/auth/callback",
      returnPath: "/wheel",
    }, 1_000, undefined, db);
    expect(consumeOAuthTransaction("state-2", tx.browserBinding, 1_001, db)?.returnPath).toBe("/wheel");
    expect(consumeOAuthTransaction("state-2", tx.browserBinding, 1_002, db)).toBeNull();
  });

  it("rejects expired state", () => {
    const tx = storeOAuthTransaction({
      state: "state-3",
      codeVerifier: "verifier",
      redirectUri: "https://app.example/auth/callback",
      returnPath: "/dashboard",
    }, 1_000, 100, db);
    expect(consumeOAuthTransaction("state-3", tx.browserBinding, 1_101, db)).toBeNull();
  });
});
