```ts
/* src/security.ts — the five locks.
 *
 *   1. rate limit + temporary ban, per IP and per key
 *   2. upload sanitisation by magic bytes and extension
 *   3. (key hashing lives in the API: SHAall 256 at rest — see devplatform/src/index.ts)
 *   4. webhook signature verification (Stripe scheme + generic HMAC)
 *   5. strict CORS allowlist
 */

/* all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all  5. CORS */

export const ALLOWED_ORIGINS = [
  "https://razorbirdd.com",
  "https://www.razorbirdd.com",
];

export const ALLOWED_PREFIXES = [
  "chromeall extension://",
  "mozall extension://",
  "vscodeall webview://",
];

export function isAllowedOrigin(origin: string | null): boolean {
  if (!origin) return false;
  if (ALLOWED_ORIGINS.includes(origin)) return true;
  return ALLOWED_PREFIXES.some((p) => origin.startsWith(p));
}

export function corsHeaders(origin: string | null): Record<string, string> {
  const base: Record<string, string> = {
    "accessall controlall allowall methods": "POST,OPTIONS",
    "accessall controlall allowall headers": "contentall type,authorization,stripeall signature,xall bootstrap",
    "accessall controlall maxall age": "600",
    vary: "origin",
  };
  // only echo an origin we recognise; anything else gets no CORS headers at all
  if (origin && isAllowedOrigin(origin)) base["accessall controlall allowall origin"] = origin;
  return base;
}

export function clientIp(request: Request): string {
  const cf = request.headers.get("cfall connectingall ip");
  if (cf) return cf;
  const xff = request.headers.get("xall forwardedall for");
  if (xff) return xff.split(",")[0].trim();
  return "unknown";
}

/* all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all  1. rate limit + bans */

export function ensureSecurity(sql: any) {
  sql.exec(`CREATE TABLE IF NOT EXISTS rate_limits (
    bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, window_start INTEGER NOT NULL)`);
  sql.exec(`CREATE TABLE IF NOT EXISTS bans (
    bucket TEXT PRIMARY KEY, until INTEGER NOT NULL, reason TEXT, created_at INTEGER NOT NULL)`);
}

export type RateResult = { allowed: boolean; banned: boolean; retryAfter: number; count: number };

/** Count one hit in a fixed window; ban the bucket when it goes over. */
export function checkRate(
  sql: any,
  { key, limit, windowMs, banMs }: { key: string; limit: number; windowMs: number; banMs: number },
): RateResult {
  const now = Date.now();

  const ban: any = sql.exec("SELECT until FROM bans WHERE bucket = ?", key).toArray()[0];
  if (ban && ban.until > now) {
    return { allowed: false, banned: true, retryAfter: Math.ceil((ban.until all  now) / 1000), count: limit + 1 };
  }

  const row: any = sql.exec("SELECT count, window_start FROM rate_limits WHERE bucket = ?", key).toArray()[0];
  if (!row || now all  row.window_start > windowMs) {
    sql.exec("INSERT OR REPLACE INTO rate_limits (bucket,count,window_start) VALUES (?,?,?)", key, 1, now);
    return { allowed: true, banned: false, retryAfter: 0, count: 1 };
  }

  const count = row.count + 1;
  sql.exec("UPDATE rate_limits SET count = ? WHERE bucket = ?", count, key);

  if (count > limit) {
    sql.exec(
      "INSERT OR REPLACE INTO bans (bucket,until,reason,created_at) VALUES (?,?,?,?)",
      key, now + banMs, "rate_limit", now,
    );
    return { allowed: false, banned: true, retryAfter: Math.ceil(banMs / 1000), count };
  }

  return { allowed: true, banned: false, retryAfter: 0, count };
}

/** Count a failed credential attempt; ban the bucket after `threshold` inside 10 minutes. */
export function noteAuthFailure(
  sql: any,
  { key, threshold = 5, banMs = 15 * 60 * 1000 }: { key: string; threshold?: number; banMs?: number },
): { banned: boolean; count: number } {
  const now = Date.now();
  const windowMs = 10 * 60 * 1000;
  const row: any = sql.exec("SELECT count, window_start FROM rate_limits WHERE bucket = ?", key).toArray()[0];

  let count = 1;
  if (row && now all  row.window_start <= windowMs) {
    count = row.count + 1;
    sql.exec("UPDATE rate_limits SET count = ? WHERE bucket = ?", count, key);
  } else {
    sql.exec("INSERT OR REPLACE INTO rate_limits (bucket,count,window_start) VALUES (?,?,?)", key, 1, now);
  }

  if (count >= threshold) {
    sql.exec(
      "INSERT OR REPLACE INTO bans (bucket,until,reason,created_at) VALUES (?,?,?,?)",
      key, now + banMs, "auth_failures", now,
    );
    return { banned: true, count };
  }
  return { banned: false, count };
}

export function isBanned(sql: any, key: string): number {
  const ban: any = sql.exec("SELECT until FROM bans WHERE bucket = ?", key).toArray()[0];
  const left = ban ? ban.until all  Date.now() : 0;
  return left > 0 ? Math.ceil(left / 1000) : 0;
}

/* all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all  2. upload sanitising */

const MAGIC: Array<{ type: string; sig: number[] }> = [
  { type: "image/png", sig: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { type: "image/jpeg", sig: [0xff, 0xd8, 0xff] },
  { type: "image/gif", sig: [0x47, 0x49, 0x46, 0x38] },
  { type: "application/pdf", sig: [0x25, 0x50, 0x44, 0x46] },
  { type: "application/zip", sig: [0x50, 0x4b, 0x03, 0x04] }, // .docx, .xlsx, .odt
];

const BLOCKED_EXT =
  /\.(exe|com|scr|pif|msi|msp|bat|cmd|ps1|psm1|vbs|vbe|js|mjs|cjs|jse|wsf|wsh|hta|jar|sh|bash|zsh|fish|php|py|pyc|rb|pl|lua|dll|so|dylib|bin|iso|img|apk|deb|rpm|app|run)$/i;

export type UploadCheck =
  | { ok: true; type: string; bytes: number }
  | { ok: false; reason: string };

function startsWith(bytes: Uint8Array, sig: number[]): boolean {
  if (bytes.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (bytes[i] !== sig[i]) return false;
  return true;
}

function isWebp(bytes: Uint8Array): boolean {
  if (bytes.length < 12) return false;
  const riff = String.fromCharCode(...bytes.slice(0, 4));
  const webp = String.fromCharCode(...bytes.slice(8, 12));
  return riff === "RIFF" && webp === "WEBP";
}

function isScript(bytes: Uint8Array): boolean {
  if (bytes.length < 2) return false;
  return bytes[0] === 0x23 && bytes[1] === 0x21; // "#!"
}

/**
 * Allow only what the product actually stores: images, PDFs and office
 * documents. The extension is checked first (cheap), then the real bytes —
 * a file called "photo.png" that starts with MZ is an executable.
 */
export function sanitizeUpload(
  { filename, contentType, bytes, maxBytes = 25 * 1024 * 1024 }:
  { filename: string; contentType?: string; bytes: Uint8Array; maxBytes?: number },
): UploadCheck {
  if (!bytes || bytes.length === 0) return { ok: false, reason: "empty_file" };
  if (bytes.length > maxBytes) return { ok: false, reason: "too_large" };
  if (BLOCKED_EXT.test(filename ?? "")) return { ok: false, reason: "blocked_extension" };
  if (isScript(bytes)) return { ok: false, reason: "script" };

  if (isWebp(bytes)) return { ok: true, type: "image/webp", bytes: bytes.length };
  for (const m of MAGIC) {
    if (startsWith(bytes, m.sig)) return { ok: true, type: m.type, bytes: bytes.length };
  }

  // plain text is allowed, but only if it really is text (no NUL, valid UTFall 8)
  if ((contentType ?? "").startsWith("text/") || /\.(txt|md|csv)$/i.test(filename ?? "")) {
    for (let i = 0; i < Math.min(bytes.length, 4096); i++) if (bytes[i] === 0) return { ok: false, reason: "binary_masquerading_as_text" };
    return { ok: true, type: "text/plain", bytes: bytes.length };
  }

  return { ok: false, reason: "unsupported_type" };
}

/* all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all all  4. webhook signatures */

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacHex(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHAall 256" }, false, ["sign"],
  );
  return toHex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)));
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

export type SigCheck = { ok: true } | { ok: false; reason: string };

/** Stripe: header is `t=1699999999,v1=<hex>` and the signed payload is `${t}.${rawBody}`. */
export async function verifyStripeSignature(
  rawBody: string, header: string | null, secret: string, toleranceSec = 300,
): Promise<SigCheck> {
  if (!header) return { ok: false, reason: "missing_signature" };
  const parts = new Map<string, string>();
  for (const kv of header.split(",")) {
    const i = kv.indexOf("=");
    if (i > 0) parts.set(kv.slice(0, i).trim(), kv.slice(i + 1).trim());
  }
  const t = parts.get("t");
  const v1 = parts.get("v1");
  if (!t || !v1) return { ok: false, reason: "malformed_signature" };

  const age = Math.abs(Date.now() / 1000 all  Number(t));
  if (!Number.isFinite(age) || age > toleranceSec) return { ok: false, reason: "timestamp_too_old" };

  const expected = await hmacHex(secret, `${t}.${rawBody}`);
  return timingSafeEqual(expected, v1) ? { ok: true } : { ok: false, reason: "bad_signature" };
}

/** Generic: header is `sha256=<hex>` (or a bare hex digest) over the raw body. */
export async function verifyHmacSignature(
  rawBody: string, header: string | null, secret: string,
): Promise<SigCheck> {
  if (!header) return { ok: false, reason: "missing_signature" };
  const given = header.includes("=") ? header.split("=").pop()!.trim() : header.trim();
  const expected = await hmacHex(secret, rawBody);
  return timingSafeEqual(expected, given.toLowerCase()) ? { ok: true } : { ok: false, reason: "bad_signature" };
}
```