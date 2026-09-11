import {
  pgTable,
  text,
  integer,
  bigint,
  timestamp,
  jsonb,
  boolean,
  real,
  serial,
  uniqueIndex,
  index,
} from "drizzle-orm/pg-core";

/**
 * Project database.
 *
 * One row per distinct binary (identified by SHA-256). All user annotations,
 * AI observations and cached analysis snapshots hang off this identity so a
 * binary can be re-opened later and everything is restored without re-doing
 * work. The original binary is never modified.
 */
export const binaries = pgTable("binaries", {
  hash: text("hash").primaryKey(), // sha256 hex
  fileName: text("file_name").notNull(),
  size: bigint("size", { mode: "number" }).notNull(),
  arch: text("arch").notNull(),
  elfClass: integer("elf_class").notNull(),
  endianness: text("endianness").notNull(),
  analysisVersion: text("analysis_version").notNull(),
  analysisState: text("analysis_state").notNull().default("pending"), // pending | partial | complete
  summary: jsonb("summary").$type<Record<string, unknown>>().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  openedAt: timestamp("opened_at", { withTimezone: true }).defaultNow().notNull(),
});

/** User-defined / accepted names for addresses (functions, globals, strings). */
export const names = pgTable(
  "names",
  {
    id: serial("id").primaryKey(),
    binaryHash: text("binary_hash")
      .notNull()
      .references(() => binaries.hash, { onDelete: "cascade" }),
    address: bigint("address", { mode: "number" }).notNull(),
    name: text("name").notNull(),
    origin: text("origin").notNull(), // user | ai-accepted
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [uniqueIndex("names_binary_addr_idx").on(t.binaryHash, t.address)],
);

export const comments = pgTable(
  "comments",
  {
    id: serial("id").primaryKey(),
    binaryHash: text("binary_hash")
      .notNull()
      .references(() => binaries.hash, { onDelete: "cascade" }),
    address: bigint("address", { mode: "number" }).notNull(),
    scope: text("scope").notNull().default("line"), // line | function
    body: text("body").notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [uniqueIndex("comments_binary_addr_scope_idx").on(t.binaryHash, t.address, t.scope)],
);

export const bookmarks = pgTable(
  "bookmarks",
  {
    id: serial("id").primaryKey(),
    binaryHash: text("binary_hash")
      .notNull()
      .references(() => binaries.hash, { onDelete: "cascade" }),
    address: bigint("address", { mode: "number" }).notNull(),
    kind: text("kind").notNull().default("address"), // address | function | string | data
    label: text("label").notNull(),
    note: text("note").default(""),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [uniqueIndex("bookmarks_binary_addr_idx").on(t.binaryHash, t.address)],
);

export const tags = pgTable(
  "tags",
  {
    id: serial("id").primaryKey(),
    binaryHash: text("binary_hash")
      .notNull()
      .references(() => binaries.hash, { onDelete: "cascade" }),
    address: bigint("address", { mode: "number" }).notNull(),
    tag: text("tag").notNull(),
  },
  (t) => [uniqueIndex("tags_binary_addr_tag_idx").on(t.binaryHash, t.address, t.tag)],
);

/** User-defined structures (fields stored as JSON). */
export const structures = pgTable("structures", {
  id: serial("id").primaryKey(),
  binaryHash: text("binary_hash")
    .notNull()
    .references(() => binaries.hash, { onDelete: "cascade" }),
  name: text("name").notNull(),
  origin: text("origin").notNull().default("user"), // user | inferred | ai
  fields: jsonb("fields").$type<{ offset: number; name: string; size: number; type?: string; certain: boolean }[]>().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

/** Every AI conclusion is stored with evidence and the user's verdict. */
export const aiObservations = pgTable(
  "ai_observations",
  {
    id: serial("id").primaryKey(),
    binaryHash: text("binary_hash")
      .notNull()
      .references(() => binaries.hash, { onDelete: "cascade" }),
    address: bigint("address", { mode: "number" }).notNull(),
    kind: text("kind").notNull(), // name-suggestion | classification | explanation
    content: text("content").notNull(),
    confidence: real("confidence").notNull(),
    evidence: jsonb("evidence").$type<{ address?: number; text: string }[]>().default([]),
    verdict: text("verdict").notNull().default("pending"), // pending | accepted | rejected
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [index("ai_obs_binary_addr_idx").on(t.binaryHash, t.address)],
);

/**
 * Cached analysis output (functions, classifications, strings summary...).
 * Stored per stage so partially completed analysis can be recovered after a crash.
 */
export const analysisSnapshots = pgTable(
  "analysis_snapshots",
  {
    id: serial("id").primaryKey(),
    binaryHash: text("binary_hash")
      .notNull()
      .references(() => binaries.hash, { onDelete: "cascade" }),
    stage: text("stage").notNull(),
    analysisVersion: text("analysis_version").notNull(),
    complete: boolean("complete").notNull().default(false),
    payload: jsonb("payload").notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [uniqueIndex("snapshots_binary_stage_idx").on(t.binaryHash, t.stage)],
);

/** Reusable byte signatures (wildcards supported). */
export const signatures = pgTable("signatures", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  pattern: text("pattern").notNull(),
  description: text("description").default(""),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const settings = pgTable("settings", {
  key: text("key").primaryKey(),
  value: jsonb("value").notNull(),
});
