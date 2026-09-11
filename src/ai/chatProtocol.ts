/**
 * Wire protocol shared by the AI panel (client) and /api/ai/chat (server).
 * Pure types + pure helpers — no React, no Node APIs — so both sides and the
 * tests import the same definitions.
 */
export interface ChatTurn {
  role: "user" | "assistant";
  content: string;
}

export interface ChatRequest {
  question: string;
  /** Pre-rendered, size-capped plaintext context (see ai/context.ts). */
  contextText: string;
  /** Deterministic local answer the LLM must stay grounded in. */
  localAnswer?: string;
  history?: ChatTurn[];
}

/** One NDJSON line of the streamed response. */
export type ChatEvent =
  | { t: "start"; provider: string; model: string }
  | { t: "delta"; text: string }
  | { t: "done"; text: string; stopReason: string | null; servedBy: string | null; inputTokens?: number; outputTokens?: number }
  | { t: "refusal"; category: string | null; explanation: string | null }
  | { t: "error"; error: string };

export const MAX_HISTORY_TURNS = 8;

/**
 * Make a conversation history the providers will accept:
 * - drop turns with empty content (Anthropic rejects empty text blocks),
 * - keep only the last N turns,
 * - the first turn must be a user turn,
 * - the last turn must be an assistant turn (the new question follows it).
 */
export function sanitizeHistory(turns: ChatTurn[] | undefined, maxTurns = MAX_HISTORY_TURNS): ChatTurn[] {
  const out = (turns ?? [])
    .filter((t): t is ChatTurn => !!t && (t.role === "user" || t.role === "assistant") && typeof t.content === "string" && t.content.trim().length > 0)
    .map((t) => ({ role: t.role, content: t.content.trim().slice(0, 20_000) }))
    .slice(-maxTurns);
  while (out.length && out[0].role !== "user") out.shift();
  while (out.length && out[out.length - 1].role !== "assistant") out.pop();
  return out;
}

/** Parse one NDJSON line defensively; malformed lines become error events. */
export function parseChatEvent(line: string): ChatEvent | null {
  const s = line.trim();
  if (!s) return null;
  try {
    const j = JSON.parse(s) as Partial<ChatEvent> & { t?: string };
    if (!j || typeof j.t !== "string") return { t: "error", error: `bad event: ${s.slice(0, 80)}` };
    return j as ChatEvent;
  } catch {
    return { t: "error", error: `unparseable event: ${s.slice(0, 80)}` };
  }
}
