package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"proxy/internal/security"
)

//go:embed schema.sql
var schemaSQL string

const NotifyChannel = "pxproxy_changes"

const (
	lockIDConfig  = 90210
	writeTimeout  = 5 * time.Second
	notifyTimeout = 3 * time.Second
)

type PgBackend struct {
	pool *pgxpool.Pool
}

func Connect(ctx context.Context, dsn string) (*PgBackend, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: dsn invalido: %w", err)
	}
	cfg.MaxConns = 4
	cfg.MinConns = 1
	cfg.MaxConnLifetime = time.Hour
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	b := &PgBackend{pool: pool}
	if err := b.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return b, nil
}

func (b *PgBackend) migrate(ctx context.Context) error {
	mctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := b.pool.Exec(mctx, schemaSQL)
	return err
}

func (b *PgBackend) Name() string { return "postgres" }

func (b *PgBackend) Close() { b.pool.Close() }

func (b *PgBackend) Ping(ctx context.Context) error {
	c, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()
	return b.pool.Ping(c)
}

func (b *PgBackend) Load(ctx context.Context) ([]byte, error) {
	c, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	var data []byte
	err := b.pool.QueryRow(c, `SELECT data FROM pxproxy_config WHERE id = 1`).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrBackendUnavailable
	}
	return data, nil
}

func (b *PgBackend) Save(ctx context.Context, data []byte) error {
	c, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	tx, err := b.pool.Begin(c)
	if err != nil {
		return ErrBackendUnavailable
	}
	defer tx.Rollback(c)
	if _, err := tx.Exec(c, `SELECT pg_advisory_xact_lock($1)`, lockIDConfig); err != nil {
		return ErrBackendUnavailable
	}
	if _, err := tx.Exec(c, `
		INSERT INTO pxproxy_config (id, data, updated_at) VALUES (1, $1, now())
		ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()
	`, data); err != nil {
		return ErrBackendUnavailable
	}
	if _, err := tx.Exec(c, `SELECT pg_notify($1, '')`, NotifyChannel); err != nil {
		return ErrBackendUnavailable
	}
	return tx.Commit(c)
}

func (b *PgBackend) Version(ctx context.Context) (string, error) {
	c, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()
	var v string
	err := b.pool.QueryRow(c, `SELECT COALESCE(to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US'), '') FROM pxproxy_config WHERE id = 1`).Scan(&v)
	if err != nil {
		return "", ErrBackendUnavailable
	}
	return "db:" + v, nil
}

func (b *PgBackend) SaveLocks(ctx context.Context, states map[string]json.RawMessage) error {
	c, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	tx, err := b.pool.Begin(c)
	if err != nil {
		return ErrBackendUnavailable
	}
	defer tx.Rollback(c)
	if _, err := tx.Exec(c, `SELECT pg_advisory_xact_lock($1)`, lockIDConfig+1); err != nil {
		return ErrBackendUnavailable
	}
	for name, raw := range states {
		merged := mergeLockStates(name, raw, func() json.RawMessage {
			var existing json.RawMessage
			_ = tx.QueryRow(c, `SELECT state FROM pxproxy_locks WHERE name = $1`, name).Scan(&existing)
			return existing
		}())
		if _, err := tx.Exec(c, `
			INSERT INTO pxproxy_locks (name, state, updated_at) VALUES ($1, $2, now())
			ON CONFLICT (name) DO UPDATE SET state = EXCLUDED.state, updated_at = now()
		`, name, merged); err != nil {
			return ErrBackendUnavailable
		}
	}
	return tx.Commit(c)
}

func mergeLockStates(name string, incoming json.RawMessage, existing json.RawMessage) json.RawMessage {
	if len(existing) == 0 {
		return incoming
	}
	var inSt, exSt security.LimiterState
	if err := json.Unmarshal(incoming, &inSt); err != nil {
		return incoming
	}
	if err := json.Unmarshal(existing, &exSt); err != nil {
		return incoming
	}
	if inSt.Entries == nil {
		inSt.Entries = make(map[string]security.LockEntry)
	}
	for k, e := range exSt.Entries {
		cur, ok := inSt.Entries[k]
		if !ok || e.LockedUntil.After(cur.LockedUntil) || (e.LockedUntil.Equal(cur.LockedUntil) && e.Count > cur.Count) {
			inSt.Entries[k] = e
		}
	}
	out, err := json.Marshal(&inSt)
	if err != nil {
		return incoming
	}
	return out
}

func (b *PgBackend) LoadLocks(ctx context.Context) (map[string]json.RawMessage, error) {
	c, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	rows, err := b.pool.Query(c, `SELECT name, state FROM pxproxy_locks`)
	if err != nil {
		return nil, ErrBackendUnavailable
	}
	defer rows.Close()
	out := make(map[string]json.RawMessage)
	for rows.Next() {
		var name string
		var raw json.RawMessage
		if err := rows.Scan(&name, &raw); err != nil {
			continue
		}
		out[name] = raw
	}
	return out, rows.Err()
}

func (b *PgBackend) AppendAudit(ctx context.Context, event, ip, user, detail string) error {
	c, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	_, err := b.pool.Exec(c,
		`INSERT INTO pxproxy_audit (event, ip, usr, detail) VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''))`,
		event, ip, user, detail)
	if err != nil {
		return ErrBackendUnavailable
	}
	return nil
}

const backupQueryTimeout = 120 * time.Second

func (b *PgBackend) Backup(ctx context.Context) (*Snapshot, error) {
	c, cancel := context.WithTimeout(ctx, backupQueryTimeout)
	defer cancel()
	snap := &Snapshot{
		Schema:    BackupSchema,
		CreatedAt: time.Now().UTC(),
		Source:    "postgres",
		Counts:    map[string]int{},
	}
	specs := []struct {
		name string
		sql  string
	}{
		{"pxproxy_config", `SELECT COALESCE(row_to_json(t)::text, 'null') FROM (SELECT * FROM pxproxy_config ORDER BY id) t`},
		{"pxproxy_locks", `SELECT COALESCE(row_to_json(t)::text, 'null') FROM (SELECT * FROM pxproxy_locks ORDER BY name) t`},
		{"pxproxy_audit", `SELECT COALESCE(row_to_json(t)::text, 'null') FROM (SELECT * FROM pxproxy_audit ORDER BY id) t`},
	}
	for _, sp := range specs {
		rows, err := b.pool.Query(c, sp.sql)
		if err != nil {
			return nil, fmt.Errorf("%w (%s)", ErrBackendUnavailable, sp.name)
		}
		ts := TableSnapshot{Name: sp.name}
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return nil, err
			}
			ts.Rows = append(ts.Rows, json.RawMessage(raw))
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		snap.Counts[sp.name] = len(ts.Rows)
		snap.Tables = append(snap.Tables, ts)
	}
	return snap, nil
}

func (b *PgBackend) Restore(ctx context.Context, snap *Snapshot) (map[string]int, error) {
	c, cancel := context.WithTimeout(ctx, backupQueryTimeout)
	defer cancel()
	tx, err := b.pool.Begin(c)
	if err != nil {
		return nil, ErrBackendUnavailable
	}
	defer tx.Rollback(c)
	if _, err := tx.Exec(c, `SELECT pg_advisory_xact_lock($1)`, lockIDConfig); err != nil {
		return nil, ErrBackendUnavailable
	}
	done := map[string]int{}
	for _, table := range []string{"pxproxy_locks", "pxproxy_audit", "pxproxy_config"} {
		rows := snap.Table(table)
		if _, err := tx.Exec(c, `TRUNCATE `+table+` RESTART IDENTITY CASCADE`); err != nil {
			return nil, fmt.Errorf("vaciando %s: %w", table, err)
		}
		var rerr error
		switch table {
		case "pxproxy_locks":
			rerr = b.restoreLockRow(c, tx, rows)
		case "pxproxy_audit":
			rerr = b.restoreAuditRow(c, tx, rows)
		case "pxproxy_config":
			rerr = b.restoreConfigRow(c, tx, rows)
		}
		if rerr != nil {
			return nil, fmt.Errorf("restaurando %s: %w", table, rerr)
		}
		done[table] = len(rows)
	}
	if _, err := tx.Exec(c, `SELECT pg_notify($1, '')`, NotifyChannel); err != nil {
		return nil, err
	}
	if err := tx.Commit(c); err != nil {
		return nil, ErrBackendUnavailable
	}
	return done, nil
}

func decodeRow[T any](r json.RawMessage) (*T, error) {
	var v T
	if err := json.Unmarshal(r, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (b *PgBackend) restoreConfigRow(c context.Context, tx pgx.Tx, rows []json.RawMessage) error {
	if len(rows) == 0 {
		return nil
	}
	type cfgRow struct {
		ID   int             `json:"id"`
		Data json.RawMessage `json:"data"`
	}
	r, err := decodeRow[cfgRow](rows[0])
	if err != nil {
		return err
	}
	data := r.Data
	if len(data) == 0 || string(data) == "null" {
		return ErrBadSnapshot
	}
	_, err = tx.Exec(c,
		`INSERT INTO pxproxy_config (id, data, updated_at) VALUES ($1, $2, now())
		 ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`, r.ID, data)
	return err
}

func (b *PgBackend) restoreLockRow(c context.Context, tx pgx.Tx, rows []json.RawMessage) error {
	type lockRow struct {
		Name  string          `json:"name"`
		State json.RawMessage `json:"state"`
	}
	for _, raw := range rows {
		r, err := decodeRow[lockRow](raw)
		if err != nil || r.Name == "" || len(r.State) == 0 {
			continue
		}
		if _, err := tx.Exec(c,
			`INSERT INTO pxproxy_locks (name, state, updated_at) VALUES ($1, $2, now())
			 ON CONFLICT (name) DO UPDATE SET state = EXCLUDED.state, updated_at = now()`, r.Name, r.State); err != nil {
			return err
		}
	}
	return nil
}

func (b *PgBackend) restoreAuditRow(c context.Context, tx pgx.Tx, rows []json.RawMessage) error {
	type auditRow struct {
		ID     int64     `json:"id"`
		TS     time.Time `json:"ts"`
		Event  string    `json:"event"`
		IP     string    `json:"ip"`
		User   *string   `json:"usr"`
		Detail *string   `json:"detail"`
	}
	for _, raw := range rows {
		r, err := decodeRow[auditRow](raw)
		if err != nil || r.Event == "" {
			continue
		}
		if _, err := tx.Exec(c,
			`INSERT INTO pxproxy_audit (id, ts, event, ip, usr, detail) OVERRIDING SYSTEM VALUE VALUES ($1, $2, $3, $4, $5, $6)`,
			r.ID, r.TS, r.Event, r.IP, r.User, r.Detail); err != nil {
			return err
		}
		if _, err := tx.Exec(c, `SELECT setval(pg_get_serial_sequence('pxproxy_audit', 'id'), $1)`, r.ID); err != nil {
			return err
		}
	}
	return nil
}

func (b *PgBackend) WatchChanges(ctx context.Context, onChange func(version string)) {
	go func() {
		for ctx.Err() == nil {
			conn, err := b.pool.Acquire(ctx)
			if err != nil {
				sleepCtx(ctx, 5*time.Second)
				continue
			}
			c := conn.Conn()
			if _, err := c.Exec(ctx, fmt.Sprintf("LISTEN %s", NotifyChannel)); err != nil {
				conn.Release()
				sleepCtx(ctx, 5*time.Second)
				continue
			}
			for {
				n, err := c.WaitForNotification(ctx)
				if err != nil {
					break
				}
				if n != nil && onChange != nil {
					onChange(b.versionSafe())
				}
			}
			conn.Release()
			sleepCtx(ctx, time.Second)
		}
	}()
}

func (b *PgBackend) versionSafe() string {
	v, _ := b.Version(context.Background())
	return v
}

func (b *PgBackend) CurrentVersion() string { return b.versionSafe() }

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func StatesFromLimiter(m map[string]*security.LimiterState) (map[string]json.RawMessage, error) {
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		out[k] = raw
	}
	return out, nil
}

func StatesToLimiter(raw map[string]json.RawMessage) map[string]*security.LimiterState {
	out := make(map[string]*security.LimiterState, len(raw))
	for k, r := range raw {
		st := new(security.LimiterState)
		if err := json.Unmarshal(r, st); err != nil {
			continue
		}
		out[k] = st
	}
	return out
}
