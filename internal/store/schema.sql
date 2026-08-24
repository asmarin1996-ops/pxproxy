CREATE TABLE IF NOT EXISTS pxproxy_config (
    id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    data jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pxproxy_locks (
    name text PRIMARY KEY,
    state jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pxproxy_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts timestamptz NOT NULL DEFAULT now(),
    event text NOT NULL,
    ip text NOT NULL DEFAULT '',
    usr text,
    detail text
);

CREATE INDEX IF NOT EXISTS idx_pxproxy_audit_ts ON pxproxy_audit (ts DESC);
CREATE INDEX IF NOT EXISTS idx_pxproxy_audit_event ON pxproxy_audit (event);
