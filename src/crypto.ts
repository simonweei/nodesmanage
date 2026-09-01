import { x25519 } from "@noble/curves/ed25519.js";

const encoder = new TextEncoder();

function base64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function clampX25519PrivateKey(value: Uint8Array): Uint8Array {
  if (value.length !== 32) throw new Error("Reality private key must contain 32 bytes");
  const result = value.slice();
  result[0] = result[0]! & 248;
  result[31] = (result[31]! & 127) | 64;
  return result;
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function hmacHex(secret: string, message: string): Promise<string> {
  if (secret.length < 32) throw new Error("AGENT_TOKEN_SECRET must contain at least 32 characters");
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function randomToken(bytes = 32): string {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function randomUuid(): string {
  return crypto.randomUUID();
}

export function randomBase64(bytes: number): string {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export async function realityKeypair(): Promise<{ private_key: string; public_key: string }> {
  const privateKey = clampX25519PrivateKey(crypto.getRandomValues(new Uint8Array(32)));
  return { private_key: base64Url(privateKey), public_key: base64Url(x25519.getPublicKey(privateKey)) };
}

export function realityPrivateKey(privateKey: string): string {
  return base64Url(clampX25519PrivateKey(decodeBase64Url(privateKey)));
}

export function realityPublicKey(privateKey: string): string {
  const decoded = clampX25519PrivateKey(decodeBase64Url(privateKey));
  return base64Url(x25519.getPublicKey(decoded));
}
