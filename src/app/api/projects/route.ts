import { getDb } from "@/db";
import { binaries } from "@/db/schema";
import { desc, sql } from "drizzle-orm";

export const dynamic = "force-dynamic";

/** Project DB is optional — without DATABASE_URL the workbench still analyses, it just can't persist. Answer 200 (not 500) so the console stays clean. */
function dbError(e: unknown) {
  const msg = String(e);
  if (msg.includes("DATABASE_URL")) return Response.json({ ok: false, disabled: true, error: msg });
  return Response.json({ ok: false, error: msg }, { status: 500 });
}

export async function GET() {
  try {
    const db = getDb();
    const rows = await db.select().from(binaries).orderBy(desc(binaries.openedAt)).limit(50);
    return Response.json({ ok: true, projects: rows });
  } catch (e) {
    return dbError(e);
  }
}

/** Upsert a binary identity (called once the SHA-256 is known). */
export async function POST(req: Request) {
  try {
    const db = getDb();
    const body = await req.json();
    const { hash, fileName, size, arch, elfClass, endianness, analysisVersion } = body ?? {};
    if (typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)) return Response.json({ ok: false, error: "invalid hash" }, { status: 400 });
    const [row] = await db
      .insert(binaries)
      .values({ hash, fileName: String(fileName ?? "binary"), size: Number(size ?? 0), arch: String(arch ?? "unknown"), elfClass: Number(elfClass ?? 64), endianness: String(endianness ?? "little"), analysisVersion: String(analysisVersion ?? "0") })
      .onConflictDoUpdate({ target: binaries.hash, set: { openedAt: sql`now()`, fileName: String(fileName ?? "binary") } })
      .returning();
    return Response.json({ ok: true, project: row });
  } catch (e) {
    return dbError(e);
  }
}
