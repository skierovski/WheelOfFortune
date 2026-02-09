import crypto from "crypto";

const ALGO = "aes-256-gcm";
const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * Derive a 32-byte key from the hex secret string.
 * Uses SHA-256 so the key works regardless of the raw secret length.
 */
function deriveKey(secret) {
  return crypto.createHash("sha256").update(secret, "utf8").digest();
}

/**
 * Encrypt a plaintext string using AES-256-GCM.
 *
 * @param {string} plaintext  The value to encrypt
 * @param {string} secret     Hex key string (from env.ENCRYPTION_KEY)
 * @returns {string}           Format: base64(iv + authTag + ciphertext)
 */
export function encrypt(plaintext, secret) {
  if (!plaintext) return plaintext;
  const key = deriveKey(secret);
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Pack: iv (12) + tag (16) + ciphertext (variable)
  const packed = Buffer.concat([iv, tag, encrypted]);
  return packed.toString("base64");
}

/**
 * Decrypt a value encrypted by encrypt().
 *
 * @param {string} encoded  The base64-encoded encrypted string
 * @param {string} secret   Same hex key used for encryption
 * @returns {string}         Original plaintext
 * @throws {Error}           If decryption fails (wrong key or tampered data)
 */
export function decrypt(encoded, secret) {
  if (!encoded) return encoded;
  const key = deriveKey(secret);
  const packed = Buffer.from(encoded, "base64");
  if (packed.length < IV_BYTES + TAG_BYTES + 1) {
    throw new Error("Invalid encrypted data: too short");
  }
  const iv = packed.subarray(0, IV_BYTES);
  const tag = packed.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
  const ciphertext = packed.subarray(IV_BYTES + TAG_BYTES);
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString("utf8");
}
