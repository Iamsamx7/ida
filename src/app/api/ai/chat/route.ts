import Anthropic from "@anthropic-ai/sdk";
import { anthropicCapabilities, providerStatus, type ProviderStatus } from "@/ai/providers";
import { sanitizeHistory, type ChatEvent, type ChatRequest, type ChatTurn } from "@/ai/chatProtocol";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

const REQUEST_TIMEOUT_MS = 180_000;
const MAX_TOKENS = 16_000;

/**
 * LLM proxy. The client sends the question, the deterministic local answer and
 * a pre-rendered context; this route streams the provider's prose back as
 * NDJSON events (see ai/chatProtocol.ts). Secrets never reach the browser.
 *
 * Anthropic goes through the official SDK (streaming, adaptive thinking,
 * effort, typed errors, refusal stop reason). Any OpenAI-compatible endpoint
 * (OPENAI_API_KEY / AI_BASE_URL) is driven over raw SSE.
 */
const SYSTEM = `You are a senior reverse engineer embedded in soforge, a native ELF/.so analysis workbench. Primary targets: Android ARM64 game libraries (Unreal/Unity, PUBG-style) and their protection layers (Anogs/TSS/ACE-style anticheat, integrity hashing, ban enforcement, emulator/root/debugger probes).

You receive the user's question, a LOCAL ENGINE ANSWER produced deterministically from the analysis database (every address in it has already been cross-checked), and STRUCTURED CONTEXT: disassembly, reconstructed pseudocode, xrefs, strings, rule-engine classifications with evidence, verified intel findings with their proof legs, and the import→library map.

Ground rules:
- Answer from the provided context. When it is insufficient, say exactly what is missing and name the concrete thing to inspect next (an import, a string, an address, a caller).
- Separate FACT (read from the binary), INFERENCE (from patterns) and HYPOTHESIS (your interpretation). Give a confidence for interpretations; reserve certainty for known symbols.
- Write addresses as 0x… so the UI can link them; name the owning library for imports when known (memcpy [libc.so]).
- Pseudocode is reconstructed, not source. Intel proof levels: PROVEN = two independent semantic witnesses (strings + imports/constants), CORROBORATED = one, LEAD = classification and shape only. Never upgrade a lead.
- Shape: one verdict line with confidence, evidence bullets with addresses, what it is NOT, what to check next. Technical and tight; drop anything you cannot ground.`;

export async function GET() {
  const p = providerStatus();
  return Response.json({ ok: true, configured: !!p, provider: p?.provider ?? "local-evidence-engine", model: p?.model ?? null, effort: p?.effort ?? null });
}

export async function POST(req: Request) {
  const p = providerStatus();
  if (!p) return Response.json({ ok: false, configured: false, error: "No LLM provider configured; using local evidence engine." }, { status: 200 });
  let body: ChatRequest;
  try {
    body = (await req.json()) as ChatRequest;
  } catch {
    return Response.json({ ok: false, error: "bad json" }, { status: 400 });
  }
  if (!body || typeof body.question !== "string" || !body.question.trim()) return Response.json({ ok: false, error: "question required" }, { status: 400 });
  const history = sanitizeHistory(body.history);
  const user = renderUserTurn(body);
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      let open = true;
      // The client may go away mid-stream (Stop button, tab closed); writing to a closed controller throws.
      const emit = (ev: ChatEvent) => {
        if (!open) return;
        try { controller.enqueue(encoder.encode(JSON.stringify(ev) + "\n")); } catch { open = false; }
      };
      try {
        emit({ t: "start", provider: p.provider, model: p.model });
        if (p.provider === "anthropic") await streamAnthropic(p, history, user, emit, req.signal);
        else await streamOpenAICompatible(p, history, user, emit, req.signal);
      } catch (e) {
        emit({ t: "error", error: describeError(e) });
      } finally {
        if (open) { try { controller.close(); } catch { /* already closed by the consumer */ } }
      }
    },
    cancel() { /* consumer went away — providers observe req.signal */ },
  });
  return new Response(stream, { headers: { "content-type": "application/x-ndjson; charset=utf-8", "cache-control": "no-store", "x-accel-buffering": "no" } });
}

function renderUserTurn(b: ChatRequest): string {
  const ctx = (typeof b.contextText === "string" ? b.contextText : "").slice(0, 60_000);
  return `QUESTION:\n${b.question.trim().slice(0, 4_000)}\n\nLOCAL ENGINE ANSWER (deterministic, verified against the database):\n${(b.localAnswer ?? "(none)").slice(0, 12_000)}\n\nSTRUCTURED CONTEXT:\n${ctx || "(none)"}`;
}

async function streamAnthropic(p: ProviderStatus, history: ChatTurn[], user: string, emit: (ev: ChatEvent) => void, signal: AbortSignal) {
  // Zero-arg client: resolves ANTHROPIC_API_KEY, then ANTHROPIC_AUTH_TOKEN, then an `ant auth login` profile.
  const client = new Anthropic({ timeout: REQUEST_TIMEOUT_MS, maxRetries: 2 });
  const caps = anthropicCapabilities(p.model);
  const messages: Anthropic.Beta.BetaMessageParam[] = [...history.map((h) => ({ role: h.role, content: h.content })), { role: "user", content: user }];
  const stream = client.beta.messages.stream(
    {
      model: p.model,
      max_tokens: MAX_TOKENS,
      system: [{ type: "text", text: SYSTEM }],
      messages,
      ...(caps.adaptiveThinking ? { thinking: { type: "adaptive" as const } } : {}),
      ...(caps.effort ? { output_config: { effort: p.effort } } : {}),
      // Server-side refusal fallbacks: a policy decline re-runs the same request on a fallback model inside this call.
      ...(caps.fallbacks ? { betas: ["server-side-fallback-2026-07-01"], fallbacks: "default" as const } : {}),
    },
    { signal },
  );
  stream.on("text", (delta) => emit({ t: "delta", text: delta }));
  const final = await stream.finalMessage();
  const text = final.content.filter((b): b is Anthropic.Beta.BetaTextBlock => b.type === "text").map((b) => b.text).join("");
  if (final.stop_reason === "refusal") emit({ t: "refusal", category: final.stop_details?.category ?? null, explanation: final.stop_details?.explanation ?? null });
  emit({ t: "done", text, stopReason: final.stop_reason ?? null, servedBy: final.model ?? null, inputTokens: final.usage?.input_tokens, outputTokens: final.usage?.output_tokens });
}

async function streamOpenAICompatible(p: ProviderStatus, history: ChatTurn[], user: string, emit: (ev: ChatEvent) => void, signal: AbortSignal) {
  const base = (process.env.AI_BASE_URL || "https://api.openai.com/v1").replace(/\/$/, "");
  const r = await fetch(`${base}/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${process.env.OPENAI_API_KEY ?? "none"}` },
    body: JSON.stringify({ model: p.model, temperature: 0.2, max_tokens: MAX_TOKENS, stream: true, messages: [{ role: "system", content: SYSTEM }, ...history, { role: "user", content: user }] }),
    signal: AbortSignal.any([signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)]),
  });
  if (!r.ok) {
    let msg = r.statusText;
    try {
      const j = (await r.json()) as { error?: { message?: string } };
      msg = j?.error?.message ?? msg;
    } catch { /* non-JSON error body */ }
    emit({ t: "error", error: `${p.provider} HTTP ${r.status}: ${msg}` });
    return;
  }
  const ct = r.headers.get("content-type") ?? "";
  if (!r.body || ct.includes("application/json")) {
    // Endpoint ignored stream=true and answered in one piece.
    const j = (await r.json()) as { choices?: { message?: { content?: string }; finish_reason?: string }[] };
    const text = j.choices?.[0]?.message?.content ?? "";
    emit({ t: "delta", text });
    emit({ t: "done", text, stopReason: j.choices?.[0]?.finish_reason ?? null, servedBy: p.model });
    return;
  }
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  let acc = "";
  let finish: string | null = null;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line.startsWith("data:")) continue;
      const data = line.slice(5).trim();
      if (!data || data === "[DONE]") continue;
      try {
        const j = JSON.parse(data) as { choices?: { delta?: { content?: string }; finish_reason?: string | null }[] };
        const delta = j.choices?.[0]?.delta?.content;
        if (typeof delta === "string" && delta) { acc += delta; emit({ t: "delta", text: delta }); }
        if (j.choices?.[0]?.finish_reason) finish = j.choices[0].finish_reason;
      } catch { /* partial frame — wait for more */ }
    }
  }
  emit({ t: "done", text: acc, stopReason: finish, servedBy: p.model });
}

function describeError(e: unknown): string {
  if (e instanceof Anthropic.AuthenticationError) return "Anthropic rejected the credentials (401) — check ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN on the server.";
  if (e instanceof Anthropic.PermissionDeniedError) return `Anthropic: permission denied (403) — ${e.message}`;
  if (e instanceof Anthropic.NotFoundError) return `Anthropic: model not found (404) — check AI_MODEL. ${e.message}`;
  if (e instanceof Anthropic.RateLimitError) return "Anthropic rate limit (429) — retry in a moment.";
  if (e instanceof Anthropic.BadRequestError) return `Anthropic rejected the request (400): ${e.message}`;
  if (e instanceof Anthropic.APIConnectionTimeoutError) return `LLM request timed out after ${REQUEST_TIMEOUT_MS / 1000}s.`;
  if (e instanceof Anthropic.APIConnectionError) return `Could not reach the LLM endpoint: ${e.message}`;
  if (e instanceof Anthropic.APIError) return `LLM API error ${e.status ?? ""}: ${e.message}`;
  if (e instanceof Error && (e.name === "AbortError" || e.name === "TimeoutError")) return e.name === "TimeoutError" ? `LLM request timed out after ${REQUEST_TIMEOUT_MS / 1000}s.` : "cancelled";
  return e instanceof Error ? e.message : String(e);
}
