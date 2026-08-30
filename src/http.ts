export class HttpError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export function json(data: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  return Response.json(data, { ...init, headers });
}

export async function readJsonObject(request: Request, maxBytes = 64 * 1024): Promise<Record<string, unknown>> {
  const length = Number(request.headers.get("content-length") ?? "0");
  if (length > maxBytes) throw new HttpError(413, "request body too large");
  if (!request.body) throw new HttpError(400, "JSON body required");
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new HttpError(413, "request body too large");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  let body: unknown;
  try {
    body = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new HttpError(400, "invalid JSON body");
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(400, "JSON object required");
  }
  return body as Record<string, unknown>;
}

export function stringField(body: Record<string, unknown>, key: string, options: { required?: boolean; max?: number } = {}): string {
  const value = body[key];
  if (typeof value !== "string") {
    if (!options.required && value === undefined) return "";
    throw new HttpError(400, `${key} must be a string`);
  }
  const result = value.trim();
  if (options.required && result.length === 0) throw new HttpError(400, `${key} is required`);
  if (result.length > (options.max ?? 1024)) throw new HttpError(400, `${key} is too long`);
  return result;
}

export function numberField(body: Record<string, unknown>, key: string, options: { min?: number; max?: number; integer?: boolean } = {}): number | null {
  const value = body[key];
  if (value === undefined || value === null) return null;
  if (typeof value !== "number" || !Number.isFinite(value)) throw new HttpError(400, `${key} must be a number`);
  if (options.integer && !Number.isInteger(value)) throw new HttpError(400, `${key} must be an integer`);
  if (options.min !== undefined && value < options.min) throw new HttpError(400, `${key} is too small`);
  if (options.max !== undefined && value > options.max) throw new HttpError(400, `${key} is too large`);
  return value;
}

export function booleanField(body: Record<string, unknown>, key: string, fallback = false): boolean {
  const value = body[key];
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new HttpError(400, `${key} must be a boolean`);
  return value;
}
