/**
 * Mock OpenAI-compatible chat endpoint for exercising the AI panel's streaming
 * path without a real key. Streams a short markdown answer as SSE deltas and
 * echoes how much context it received.
 *
 *   node tests/mock-llm.mjs [port=8787]
 *   then in .env.local:  AI_BASE_URL=http://127.0.0.1:8787/v1  AI_MODEL=mock
 */
import http from "node:http";

const port = Number(process.argv[2] || 8787);
const server = http.createServer((req, res) => {
  if (req.method !== "POST" || !req.url?.endsWith("/chat/completions")) {
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: { message: `mock: no route for ${req.method} ${req.url}` } }));
    return;
  }
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    let j;
    try { j = JSON.parse(body); } catch { res.writeHead(400); res.end("bad json"); return; }
    const user = j.messages?.filter((m) => m.role === "user").pop()?.content ?? "";
    const q = user.match(/QUESTION:\n([^\n]*)/)?.[1] ?? "?";
    const ctxLen = (user.split("STRUCTURED CONTEXT:\n")[1] ?? "").length;
    const addrs = [...new Set(user.match(/0x[0-9a-f]{3,}/g) ?? [])].slice(0, 3);
    const text = [
      `**Verdict** — mock answer for “${q}” (confidence 42%).`,
      "",
      "## Evidence",
      `- Received ${ctxLen} chars of structured context and ${j.messages.length} message(s).`,
      ...addrs.map((a) => `- Saw address ${a} in the context (linkable).`),
      "- Inline \`code\` and a fenced block below:",
      "```",
      "MOV X0, #0 ; RET",
      "```",
      "## What to check next",
      "1. This is a mock — nothing here is analysis.",
    ].join("\n");
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
    const words = text.split(/(?<=\s)/);
    let i = 0;
    const tick = () => {
      if (i >= words.length) {
        res.write(`data: ${JSON.stringify({ choices: [{ delta: {}, finish_reason: "stop" }] })}\n\n`);
        res.write("data: [DONE]\n\n");
        res.end();
        return;
      }
      res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: words[i++] }, finish_reason: null }] })}\n\n`);
      setTimeout(tick, 25);
    };
    tick();
  });
});
server.listen(port, "127.0.0.1", () => console.log(`mock LLM listening on http://127.0.0.1:${port}/v1`));
