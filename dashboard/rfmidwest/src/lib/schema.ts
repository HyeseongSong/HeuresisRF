// lib/schema.ts
import {
  pgTable,
  bigserial,
  varchar,
  real,
  integer,
  text,
  timestamp,
  index,
} from "drizzle-orm/pg-core";

export const incidentVerdicts = pgTable(
  "incident_verdicts",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    deviceId: varchar("device_id", { length: 64 }).notNull(),
    classification: varchar("classification", { length: 64 }).notNull(),
    confidence: real("confidence").notNull(),
    meanRssi: real("mean_rssi").notNull(),
    variance: real("variance").notNull(),
    sampleCount: integer("sample_count").notNull(),
    rationale: text("rationale"),
    actionTaken: varchar("action_taken", { length: 64 }),
    rawSeries: text("raw_series"), // Stored cleanly as a standard JSON string
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("idx_verdicts_device").on(table.deviceId, table.createdAt.desc()),
  ]
);

export type InsertVerdict = typeof incidentVerdicts.$inferInsert;
export type SelectVerdict = typeof incidentVerdicts.$inferSelect;