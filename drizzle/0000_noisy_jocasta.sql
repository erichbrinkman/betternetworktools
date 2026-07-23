CREATE TABLE `feedback_rate_limits` (
	`limiter_key` text PRIMARY KEY NOT NULL,
	`request_count` integer NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `feedback_rate_limits_expires_idx` ON `feedback_rate_limits` (`expires_at`);