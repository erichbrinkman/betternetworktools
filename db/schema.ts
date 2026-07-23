import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const feedbackRateLimits = sqliteTable(
  "feedback_rate_limits",
  {
    limiterKey: text("limiter_key").primaryKey().notNull(),
    requestCount: integer("request_count").notNull(),
    expiresAt: integer("expires_at").notNull(),
  },
  (table) => [index("feedback_rate_limits_expires_idx").on(table.expiresAt)],
);
