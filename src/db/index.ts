import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

type Db = ReturnType<typeof drizzle>;

const globalForDb = globalThis as typeof globalThis & {
  __soforgePool?: Pool;
  __soforgeDb?: Db;
};

/**
 * Lazily-created database handle (one pool per process, also across Next.js
 * dev reloads). It throws only when first *used* without DATABASE_URL, so the
 * app builds and runs without a database — the API routes then answer with
 * `ok: false` and the workbench keeps working without project persistence.
 */
export function getDb(): Db {
  if (globalForDb.__soforgeDb) return globalForDb.__soforgeDb;
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL is not set; project persistence is disabled");
  const pool = globalForDb.__soforgePool ?? new Pool({ connectionString: url });
  const db = drizzle(pool);
  globalForDb.__soforgePool = pool;
  globalForDb.__soforgeDb = db;
  return db;
}
