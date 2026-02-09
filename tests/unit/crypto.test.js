import { describe, it, expect } from "vitest";
import { encrypt, decrypt } from "../../src/utils/crypto.js";

const SECRET = "a".repeat(64); // 64-char hex string

describe("crypto encrypt/decrypt", () => {
  it("round-trips: decrypt(encrypt(text)) === text", () => {
    const plaintext = "my_super_secret_access_token_12345";
    const encrypted = encrypt(plaintext, SECRET);
    const decrypted = decrypt(encrypted, SECRET);
    expect(decrypted).toBe(plaintext);
  });

  it("produces different ciphertext each time (random IV)", () => {
    const plaintext = "same_value";
    const a = encrypt(plaintext, SECRET);
    const b = encrypt(plaintext, SECRET);
    expect(a).not.toBe(b); // different IVs
    // But both decrypt to the same value
    expect(decrypt(a, SECRET)).toBe(plaintext);
    expect(decrypt(b, SECRET)).toBe(plaintext);
  });

  it("fails to decrypt with wrong key", () => {
    const encrypted = encrypt("secret_data", SECRET);
    const wrongKey = "b".repeat(64);
    expect(() => decrypt(encrypted, wrongKey)).toThrow();
  });

  it("fails to decrypt tampered ciphertext", () => {
    const encrypted = encrypt("secret_data", SECRET);
    // Flip a character in the middle of the base64 string
    const chars = encrypted.split("");
    const mid = Math.floor(chars.length / 2);
    chars[mid] = chars[mid] === "A" ? "B" : "A";
    const tampered = chars.join("");
    expect(() => decrypt(tampered, SECRET)).toThrow();
  });

  it("handles empty string input", () => {
    expect(encrypt("", SECRET)).toBe("");
    expect(decrypt("", SECRET)).toBe("");
  });

  it("handles null/undefined input", () => {
    expect(encrypt(null, SECRET)).toBeNull();
    expect(encrypt(undefined, SECRET)).toBeUndefined();
    expect(decrypt(null, SECRET)).toBeNull();
    expect(decrypt(undefined, SECRET)).toBeUndefined();
  });

  it("handles unicode content", () => {
    const text = "token with unicode: ";
    const encrypted = encrypt(text, SECRET);
    expect(decrypt(encrypted, SECRET)).toBe(text);
  });

  it("handles long tokens", () => {
    const longToken = "x".repeat(10000);
    const encrypted = encrypt(longToken, SECRET);
    expect(decrypt(encrypted, SECRET)).toBe(longToken);
  });

  it("output is valid base64", () => {
    const encrypted = encrypt("test_value", SECRET);
    expect(encrypted).toMatch(/^[A-Za-z0-9+/=_-]+$/);
    // Should be decodable
    const buf = Buffer.from(encrypted, "base64");
    expect(buf.length).toBeGreaterThan(28); // 12 IV + 16 tag + at least 1 byte
  });

  it("rejects truncated ciphertext", () => {
    const encrypted = encrypt("test_value", SECRET);
    const truncated = encrypted.slice(0, 10);
    expect(() => decrypt(truncated, SECRET)).toThrow();
  });

  it("works with short secrets (hashed to 32 bytes internally)", () => {
    const shortSecret = "short";
    const text = "test_data_12345";
    const encrypted = encrypt(text, shortSecret);
    expect(decrypt(encrypted, shortSecret)).toBe(text);
  });
});
