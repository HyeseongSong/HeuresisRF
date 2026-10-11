// lib/db.ts

import { SQL } from "bun";
import { drizzle } from "drizzle-orm/bun-sql";
import * as schema from "./schema";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL environment variable is not defined");
}

// Bun's native SQL client handles connection pooling internally
const client = new SQL(process.env.DATABASE_URL);

export const db = drizzle({ client, schema });
