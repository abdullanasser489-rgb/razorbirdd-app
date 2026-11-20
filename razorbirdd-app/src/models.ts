 exprt [spine} from "./spine";
/* src/models.ts — the closed-source model policy.
 *
 *   1. zero-data-retention, enforced at the gateway
 *   2. closed models are opt-in only; open models run inside Cloudflare
 *   3. no vault access from an external model, ever
 *   4. the UI must warn before anything leaves the secure environment
 */

export type Provider = "deepseek" | "moonshot" | "zhipu" | "mistral" | "google" | "openai" | "anthropic";

export type ModelSpec = {
  label: string;
  provider: Provider;
  /** true = leaves our environment. Requires opt-in, ZDR and PII stripping. */
  external: boolean;
  weight: number;
  multimodal?: boolean;
};

export const CATALOG: Record<string, ModelSpec> = {
  // open weights, served inside our own Cloudflare environment
  "deepseek-v4-flash": { label: "DeepSeek V4 Flash", provider: "deepseek", external: false, weight: 1.0 },
  "kimi-k2":           { label: "Kimi K2",           provider: "moonshot", external: false, weight: 1.1 },
  "glm-5.3":           { label: "GLM 5.3",           provider: "zhipu",    external: false, weight: 2.5 },
  mistral:             { label: "Mistral",           provider: "mistral",  external: false, weight: 1.1 },
  "gemma-4":           { label: "Gemma 4",           provider: "google",   external: false, weight: 1.2, multimodal: true },

  // closed source: restricted, opt-in, gateway only
  "gpt-5":             { label: "GPT-5 (OpenAI)",    provider: "openai",    external: true, weight: 3.0 },
  "claude-sonnet":     { label: "Claude Sonnet",     provider: "anthropic", external: true, weight: 3.2 },
};

export const OPEN_MODELS = Object.entries(CATALOG).filter(([, m]) => !m.external).map(([id]) => id);
export const EXTERNAL_MODELS = Object.entries(CATALOG).filter(([, m]) => m.external).map(([id]) => id);

export class PolicyError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export type ModelSource = "sandbox" | "project" | "vault";

/* ------------------------------------------- chain of responsibility text */

export const LIABILITY_TEXT =
  "External model — data leaves our secure environment. razorbirdd.com is not liable for data processed by third-party closed-source models. By continuing you accept full responsibility for that data.";

export const ACK_REQUIRED = "external_ack_required";

/* ------------------------------------------------- 1. PII stripping */

const REDACTIONS: Array<{ name: string; re: RegExp; to: string }> = [
  { name: "email", re: /[\w.+-]+@[\w-]+\.[\w.-]{2,}/gi, to: "[email]" },
  { name: "card", re: /\b(?:\d[ -]*?){13,19}\b/g, to: "[card]" },
  { name: "iban", re: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g, to: "[iban]" },
  { name: "phone", re: /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{1,4}\)[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}(?:[\s.-]?\d{2,4})?/g, to: "[phone]" },
  { name: "ipv4", re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, to: "[ip]" },
  { name: "dob", re: /\b\d{1,2}[\/.\-]\d{1,2}[\/.\-](?:19|20)\d{2}\b/g, to: "[date]" },
  { name: "postcode", re: /\b[A-Z]{1,2}\d{1,2}[A-Z]?\s?\d[A-Z]{2}\b/g, to: "[postcode]" },
];

/**
 * Strip what can be stripped reliably. Names and street addresses cannot be
 * found with a regex — so the UI says "PII stripped" and never "anonymised".
 */
export function stripPII(input: string): { text: string; redactions: Record<string, number> } {
  let text = String(input ?? "");
  const redactions: Record<string, number> = {};

  for (const rule of REDACTIONS) {
    const matches = text.match(rule.re);
    if (matches) {
      redactions[rule.name] = (redactions[rule.name] ?? 0) + matches.length;
      text = text.replace(rule.re, rule.to);
    }
  }
  return { text, redactions };
}

/* --------------------------------------- 2 + 3. the gateway decision */

export type GatewayResult = {
  model: string;
  prompt: string;
  external: boolean;
  zeroDataRetention: boolean;
  redactions: Record<string, number>;
  headers: Record<string, string>;
};

/**
 * The single place where a prompt is allowed to leave. Open models pass
 * through untouched. An external model must be opted in, may never see the
 * vault, and its prompt is redacted before it is sent anywhere.
 */
export function gateway({
  model, prompt, source = "sandbox", optIn = false,
}: { model: string; prompt: string; source?: ModelSource; optIn?: boolean }): GatewayResult {
  const spec = CATALOG[model];
  if (!spec) throw new PolicyError("unknown_model", `Unknown model: ${model}`);

  if (!spec.external) {
    return { model, prompt: String(prompt ?? ""), external: false, zeroDataRetention: true, redactions: {}, headers: {} };
  }

  // 2. opt-in only — default is off, and it is off for everyone who has not said yes
  if (!optIn) {
    throw new PolicyError(
      "external_opt_in_required",
      `${spec.label} is a closed-source model and is off by default. Turn on "Allow external models" first — nothing leaves this environment until you do.`,
    );
  }

  // 3. the vault is never readable by an external model, whatever the prompt says
  if (source === "vault") {
    throw new PolicyError(
      "vault_access_blocked",
      `Blocked: ${spec.label} cannot read your private vault. External models may only process sandbox and project data.`,
    );
  }

  // 1. zero-data-retention + PII stripping at the gateway
  const { text, redactions } = stripPII(prompt);

  return {
    model,
    prompt: text,
    external: true,
    zeroDataRetention: true,
    redactions,
    headers: {
      "x-zero-data-retention": "true",
      "x-provider": spec.provider,
      "x-redacted": Object.keys(redactions).join(",") || "none",
    },
  };
}

/** What the UI needs to draw the warning without guessing. */
export function modelOptions() {
  return Object.entries(CATALOG).map(([id, m]) => ({
    id, label: m.label, provider: m.provider, external: m.external,
    weight: m.weight, multimodal: !!m.multimodal,
    warning: m.external ? "External model — data leaves our secure environment" : null,
  }));
}
```