-- URLForensics Database Schema
-- Run with: sudo mysql urlforensics < schema.sql

SET NAMES utf8mb4;
SET time_zone = '+00:00';

-- ============================================================
-- TABLE: audits
-- One row per audit run. The central record everything hangs off.
-- ============================================================

CREATE TABLE IF NOT EXISTS audits (

    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    -- Short random string for shareable URLs: /report/aB3xKq
    -- UNIQUE enforces no two audits share a slug
    slug        VARCHAR(12) NOT NULL UNIQUE,

    -- The URL being audited — TEXT because URLs can be very long
    url         TEXT NOT NULL,

    -- Normalized domain extracted from the URL
    -- Stored separately so the watch system can query by domain efficiently
    domain      VARCHAR(255) NOT NULL,

    -- Lifecycle of an audit run
    status      ENUM('pending', 'running', 'complete', 'failed')
                NOT NULL DEFAULT 'pending',

    -- Composite trust score computed from all 6 engines (0-100)
    -- NULL until all engines finish
    trust_score TINYINT UNSIGNED NULL,

    -- Timestamps
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,

    -- Index on domain — the watch system queries "all audits for domain X"
    INDEX idx_domain (domain),

    -- Index on created_at — for "recent audits" queries
    INDEX idx_created_at (created_at)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================
-- TABLE: engine_results
-- One row per engine per audit.
-- 6 engines × 1 audit = 6 rows.
-- ============================================================

CREATE TABLE IF NOT EXISTS engine_results (

    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    -- Which audit this result belongs to
    audit_id    INT UNSIGNED NOT NULL,

    -- Which engine produced this result
    engine      ENUM(
                    'redirect_trail',
                    'dns_propagation',
                    'tls_timeline',
                    'cookie_audit',
                    'packet_journey',
                    'dns_resolution_tree'
                ) NOT NULL,

    -- Lifecycle of a single engine run
    status      ENUM('pending', 'running', 'complete', 'failed')
                NOT NULL DEFAULT 'pending',

    -- Full structured output from the engine stored as JSON
    -- MySQL's JSON type validates structure and enables JSON queries
    result      JSON NULL,

    -- Per-engine score contribution (0-100), used for trust score calc
    score       TINYINT UNSIGNED NULL,

    -- How long this engine took — useful for performance monitoring
    duration_ms INT UNSIGNED NULL,

    completed_at TIMESTAMP NULL,

    -- Foreign key — if the audit is deleted, its results are too
    CONSTRAINT fk_engine_audit
        FOREIGN KEY (audit_id)
        REFERENCES audits (id)
        ON DELETE CASCADE,

    -- Ensures one result row per engine per audit
    -- Can't have two redirect_trail rows for the same audit
    UNIQUE KEY unique_engine_per_audit (audit_id, engine),

    INDEX idx_audit_id (audit_id)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================
-- TABLE: watched_domains
-- Domains the user has saved for weekly re-auditing.
-- ============================================================

CREATE TABLE IF NOT EXISTS watched_domains (

    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    domain          VARCHAR(255) NOT NULL UNIQUE,

    -- Points to the most recent completed audit for this domain
    -- NULL until first audit completes
    last_audit_id   INT UNSIGNED NULL,

    -- When the cron job should next re-audit this domain
    next_audit_at   TIMESTAMP NOT NULL
                    DEFAULT (CURRENT_TIMESTAMP + INTERVAL 7 DAY),

    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_watch_audit
        FOREIGN KEY (last_audit_id)
        REFERENCES audits (id)
        ON DELETE SET NULL,

    -- Cron job queries: "give me all domains due for re-audit"
    INDEX idx_next_audit (next_audit_at)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;