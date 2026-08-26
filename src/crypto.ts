const encoder = new TextEncoder();

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
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
  const keys = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  const privateJwk = await crypto.subtle.exportKey("jwk", keys.privateKey) as JsonWebKey;
  const publicJwk = await crypto.subtle.exportKey("jwk", keys.publicKey) as JsonWebKey;
  if (!privateJwk.d || !publicJwk.x) throw new Error("X25519 key export failed");
  return { private_key: privateJwk.d, public_key: publicJwk.x };
}
