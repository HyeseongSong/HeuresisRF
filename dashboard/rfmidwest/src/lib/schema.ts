import { pgTable, serial, text, doublePrecision, integer } from "drizzle-orm/pg-core";

export const incidentVerdicts = pgTable("incident_verdicts", {
  id: serial("id").primaryKey(), // Uses PostgreSQL sequence (1, 2, 3...)
  deviceId: text("device_id").notNull(),
  classification: text("classification").notNull(),
  confidence: doublePrecision("confidence").notNull(),
  meanRssi: doublePrecision("mean_rssi").notNull(),
  variance: doublePrecision("variance").notNull(),
  sampleCount: integer("sample_count").notNull(),
  rationale: text("rationale").notNull(),
  actionTaken: text("action_taken").notNull(),
  rawSeries: text("raw_series").notNull(),
});