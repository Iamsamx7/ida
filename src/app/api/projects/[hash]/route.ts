import { getDb } from "@/db";
import { aiObservations, analysisSnapshots, binaries, bookmarks, comments, names, structures, tags } from "@/db/schema";
import { and, eq, sql } from "drizzle-orm";

export const dynamic = "force-dynamic";

const valid = (h: string) => /^[0-9a-f]{64}$/.test(h);

/** Project DB is optional — without DATABASE_URL answer 200 + disabled instead of 500 noise. */
function dbError(e: unknown) {
  const msg = String(e);
  if (msg.includes("DATABASE_URL")) return Response.json({ ok: false, disabled: true, error: msg });
  return Response.json({ ok: false, error: msg }, { status: 500 });
}

/** Everything needed to restore a project: annotations, AI observations, snapshot metadata. */
export async function GET(_req: Request, ctx: { params: Promise<{ hash: string }> }) {
  const { hash } = await ctx.params;
  if (!valid(hash)) return Response.json({ ok: false, error: "invalid hash" }, { status: 400 });
  try {
    const db = getDb();
    const [project] = await db.select().from(binaries).where(eq(binaries.hash, hash));
    if (!project) return Response.json({ ok: true, project: null });
    const [n, c, b, t, s, ai, snaps] = await Promise.all([
      db.select().from(names).where(eq(names.binaryHash, hash)),
      db.select().from(comments).where(eq(comments.binaryHash, hash)),
      db.select().from(bookmarks).where(eq(bookmarks.binaryHash, hash)),
      db.select().from(tags).where(eq(tags.binaryHash, hash)),
      db.select().from(structures).where(eq(structures.binaryHash, hash)),
      db.select().from(aiObservations).where(eq(aiObservations.binaryHash, hash)),
      db.select({ stage: analysisSnapshots.stage, complete: analysisSnapshots.complete, analysisVersion: analysisSnapshots.analysisVersion, updatedAt: analysisSnapshots.updatedAt }).from(analysisSnapshots).where(eq(analysisSnapshots.binaryHash, hash)),
    ]);
    return Response.json({ ok: true, project, names: n, comments: c, bookmarks: b, tags: t, structures: s, aiObservations: ai, snapshots: snaps });
  } catch (e) {
    return dbError(e);
  }
}

/** Update project metadata (analysis state, summary). */
export async function PATCH(req: Request, ctx: { params: Promise<{ hash: string }> }) {
  const { hash } = await ctx.params;
  if (!valid(hash)) return Response.json({ ok: false, error: "invalid hash" }, { status: 400 });
  try {
    const db = getDb();
    const body = await req.json();
    const set: Record<string, unknown> = {};
    if (typeof body.analysisState === "string") set.analysisState = body.analysisState;
    if (body.summary && typeof body.summary === "object") set.summary = body.summary;
    if (typeof body.analysisVersion === "string") set.analysisVersion = body.analysisVersion;
    if (!Object.keys(set).length) return Response.json({ ok: true });
    await db.update(binaries).set(set).where(eq(binaries.hash, hash));
    return Response.json({ ok: true });
  } catch (e) {
    return dbError(e);
  }
}

/**
 * Annotation mutations. Body: { type: "name"|"comment"|"bookmark"|"tag"|"structure"|"observation", op: "set"|"delete", ... }
 */
export async function PUT(req: Request, ctx: { params: Promise<{ hash: string }> }) {
  const { hash } = await ctx.params;
  if (!valid(hash)) return Response.json({ ok: false, error: "invalid hash" }, { status: 400 });
  try {
    const db = getDb();
    const body = await req.json();
    const address = Number(body.address ?? 0);
    switch (body.type) {
      case "name":
        if (body.op === "delete") await db.delete(names).where(and(eq(names.binaryHash, hash), eq(names.address, address)));
        else
          await db
            .insert(names)
            .values({ binaryHash: hash, address, name: String(body.name).slice(0, 512), origin: body.origin === "ai-accepted" ? "ai-accepted" : "user" })
            .onConflictDoUpdate({ target: [names.binaryHash, names.address], set: { name: String(body.name).slice(0, 512), origin: body.origin === "ai-accepted" ? "ai-accepted" : "user", updatedAt: sql`now()` } });
        break;
      case "comment": {
        const scope = body.scope === "function" ? "function" : "line";
        if (body.op === "delete" || !String(body.body ?? "").trim()) await db.delete(comments).where(and(eq(comments.binaryHash, hash), eq(comments.address, address), eq(comments.scope, scope)));
        else
          await db
            .insert(comments)
            .values({ binaryHash: hash, address, scope, body: String(body.body).slice(0, 8192) })
            .onConflictDoUpdate({ target: [comments.binaryHash, comments.address, comments.scope], set: { body: String(body.body).slice(0, 8192), updatedAt: sql`now()` } });
        break;
      }
      case "bookmark":
        if (body.op === "delete") await db.delete(bookmarks).where(and(eq(bookmarks.binaryHash, hash), eq(bookmarks.address, address)));
        else
          await db
            .insert(bookmarks)
            .values({ binaryHash: hash, address, kind: String(body.kind ?? "address"), label: String(body.label ?? "").slice(0, 256), note: String(body.note ?? "").slice(0, 4096) })
            .onConflictDoUpdate({ target: [bookmarks.binaryHash, bookmarks.address], set: { label: String(body.label ?? "").slice(0, 256), note: String(body.note ?? "").slice(0, 4096), kind: String(body.kind ?? "address") } });
        break;
      case "tag":
        if (body.op === "delete") await db.delete(tags).where(and(eq(tags.binaryHash, hash), eq(tags.address, address), eq(tags.tag, String(body.tag))));
        else await db.insert(tags).values({ binaryHash: hash, address, tag: String(body.tag).slice(0, 64) }).onConflictDoNothing();
        break;
      case "structure":
        if (body.op === "delete") await db.delete(structures).where(and(eq(structures.binaryHash, hash), eq(structures.id, Number(body.id))));
        else {
          const [row] = await db.insert(structures).values({ binaryHash: hash, name: String(body.name).slice(0, 128), origin: String(body.origin ?? "user"), fields: Array.isArray(body.fields) ? body.fields : [] }).returning();
          return Response.json({ ok: true, structure: row });
        }
        break;
      case "observation":
        if (body.op === "verdict") await db.update(aiObservations).set({ verdict: String(body.verdict) }).where(and(eq(aiObservations.binaryHash, hash), eq(aiObservations.id, Number(body.id))));
        else {
          const [row] = await db
            .insert(aiObservations)
            .values({ binaryHash: hash, address, kind: String(body.kind), content: String(body.content).slice(0, 8192), confidence: Number(body.confidence ?? 0), evidence: Array.isArray(body.evidence) ? body.evidence : [] })
            .returning();
          return Response.json({ ok: true, observation: row });
        }
        break;
      default:
        return Response.json({ ok: false, error: "unknown type" }, { status: 400 });
    }
    return Response.json({ ok: true });
  } catch (e) {
    return dbError(e);
  }
}
