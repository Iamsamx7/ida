import { getDb } from "@/db";
import { analysisSnapshots, binaries } from "@/db/schema";
import { and, eq, sql } from "drizzle-orm";

export const dynamic = "force-dynamic";
const valid = (h: string) => /^[0-9a-f]{64}$/.test(h);

/** Project DB is optional — without DATABASE_URL answer 200 + disabled instead of 500 noise. */
function dbError(e: unknown) {
  const msg = String(e);
  if (msg.includes("DATABASE_URL")) return Response.json({ ok: false, disabled: true, error: msg });
  return Response.json({ ok: false, error: msg }, { status: 500 });
}

/** GET ?stage=functions → cached stage payload (used to show results instantly on reopen). */
export async function GET(req: Request, ctx: { params: Promise<{ hash: string }> }) {
  const { hash } = await ctx.params;
  if (!valid(hash)) return Response.json({ ok: false, error: "invalid hash" }, { status: 400 });
  const stage = new URL(req.url).searchParams.get("stage") ?? "functions";
  try {
    const db = getDb();
    const [row] = await db.select().from(analysisSnapshots).where(and(eq(analysisSnapshots.binaryHash, hash), eq(analysisSnapshots.stage, stage)));
    return Response.json({ ok: true, snapshot: row ?? null });
  } catch (e) {
    return dbError(e);
  }
}

/** PUT { stage, analysisVersion, complete, payload } → incremental checkpoint (crash recovery / cache). */
export async function PUT(req: Request, ctx: { params: Promise<{ hash: string }> }) {
  const { hash } = await ctx.params;
  if (!valid(hash)) return Response.json({ ok: false, error: "invalid hash" }, { status: 400 });
  try {
    const db = getDb();
    const body = await req.json();
    const stage = String(body.stage ?? "functions");
    const [exists] = await db.select({ hash: binaries.hash }).from(binaries).where(eq(binaries.hash, hash));
    if (!exists) return Response.json({ ok: false, error: "unknown project" });
    await db
      .insert(analysisSnapshots)
      .values({ binaryHash: hash, stage, analysisVersion: String(body.analysisVersion ?? "0"), complete: !!body.complete, payload: body.payload ?? {} })
      .onConflictDoUpdate({ target: [analysisSnapshots.binaryHash, analysisSnapshots.stage], set: { analysisVersion: String(body.analysisVersion ?? "0"), complete: !!body.complete, payload: body.payload ?? {}, updatedAt: sql`now()` } });
    return Response.json({ ok: true });
  } catch (e) {
    return dbError(e);
  }
}
