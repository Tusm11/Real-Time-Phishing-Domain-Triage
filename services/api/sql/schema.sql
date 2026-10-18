-- Phishing-triage schema. Mounted as docker-entrypoint-initdb.d, runs
-- once on first postgres start (when the data volume is empty).

CREATE TABLE IF NOT EXISTS verdicts (
    id              BIGSERIAL PRIMARY KEY,
    domain          TEXT NOT NULL,
    cert_issuer     TEXT NOT NULL DEFAULT '',
    cert_not_before TIMESTAMPTZ,
    seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

    filter_a        DOUBLE PRECISION NOT NULL DEFAULT 999,  -- Levenshtein distance
    filter_b        DOUBLE PRECISION NOT NULL DEFAULT 0,    -- structural score
    filter_c        DOUBLE PRECISION NOT NULL DEFAULT 0,    -- embedding similarity

    matched_brand   TEXT NOT NULL DEFAULT '',
    verdict         TEXT NOT NULL CHECK (verdict IN ('phishing','suspicious','benign')),
    confidence      DOUBLE PRECISION NOT NULL,
    reasoning       TEXT NOT NULL DEFAULT '',
    model_version   TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL CHECK (source IN ('llm','fallback'))
);

CREATE INDEX IF NOT EXISTS verdicts_seen_at_idx
    ON verdicts (seen_at DESC);

CREATE INDEX IF NOT EXISTS verdicts_verdict_seen_at_idx
    ON verdicts (verdict, seen_at DESC);

CREATE INDEX IF NOT EXISTS verdicts_brand_idx
    ON verdicts (matched_brand);

-- Human-feedback labels for recall measurement.
CREATE TABLE IF NOT EXISTS labels (
    id          BIGSERIAL PRIMARY KEY,
    verdict_id  BIGINT NOT NULL REFERENCES verdicts(id) ON DELETE CASCADE,
    true_label  TEXT NOT NULL CHECK (true_label IN ('phishing','suspicious','benign')),
    labeled_by  TEXT NOT NULL DEFAULT 'operator',
    labeled_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS labels_verdict_id_idx
    ON labels (verdict_id);
