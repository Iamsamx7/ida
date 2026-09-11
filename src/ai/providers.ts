/**
 * Server-side LLM provider selection. Keys are read from the environment only
 * and never reach the browser.
 *
 *   ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN  → Anthropic (default model claude-opus-5)
 *   OPENAI_API_KEY / AI_BASE_URL              → any OpenAI-compatible endpoint
 *   AI_PROVIDER=anthropic|openai              → force one when both are configured
 *   AI_MODEL                                  → model override for either provider
 *   AI_EFFORT=low|medium|high|xhigh|max       → Anthropic reasoning effort (default high)
 */
export type ProviderId = "anthropic" | "openai-compatible";
export type Effort = "low" | "medium" | "high" | "xhigh" | "max";

export interface ProviderStatus {
  provider: ProviderId;
  model: string;
  effort: Effort;
}

export const DEFAULT_ANTHROPIC_MODEL = "claude-opus-5";
export const DEFAULT_OPENAI_MODEL = "gpt-4o-mini";
const EFFORTS: Effort[] = ["low", "medium", "high", "xhigh", "max"];

export function providerStatus(env: Record<string, string | undefined> = process.env): ProviderStatus | null {
  const hasAnthropic = !!(env.ANTHROPIC_API_KEY || env.ANTHROPIC_AUTH_TOKEN);
  const hasOpenAI = !!(env.OPENAI_API_KEY || env.AI_BASE_URL);
  const forced = (env.AI_PROVIDER ?? "").trim().toLowerCase();
  const effortRaw = (env.AI_EFFORT ?? "").trim().toLowerCase() as Effort;
  const effort: Effort = EFFORTS.includes(effortRaw) ? effortRaw : "high";
  const anthropic = (): ProviderStatus => ({ provider: "anthropic", model: env.AI_MODEL?.trim() || DEFAULT_ANTHROPIC_MODEL, effort });
  const openai = (): ProviderStatus => ({ provider: "openai-compatible", model: env.AI_MODEL?.trim() || DEFAULT_OPENAI_MODEL, effort });
  if (forced === "anthropic" && hasAnthropic) return anthropic();
  if ((forced === "openai" || forced === "openai-compatible") && hasOpenAI) return openai();
  if (hasAnthropic) return anthropic();
  if (hasOpenAI) return openai();
  return null;
}

/**
 * Which request knobs a given Anthropic model accepts. Adaptive thinking,
 * `output_config.effort` and server-side refusal fallbacks are 4.6+/5-era
 * features; sending them to Haiku 4.5 or older snapshots is a 400.
 */
export function anthropicCapabilities(model: string) {
  const m = model.toLowerCase();
  const legacy = /haiku|-4-5|-4-1|-4-0|-3-|sonnet-4-2025|opus-4-2025/.test(m);
  const fallbackTier = /claude-(fable|mythos|opus-5)/.test(m);
  return { adaptiveThinking: !legacy, effort: !legacy, fallbacks: fallbackTier };
}
