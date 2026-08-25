package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"proxy/internal/security"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("PXPX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("PXPX_TEST_PG_DSN no definido; se omite la prueba de integracion con Postgres")
	}
	return dsn
}

func TestPgConfigRoundTrip(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	b, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer b.Close()

	payload := []byte(`{"admin_port":8000,"rules":[{"host":"t.local","target":"http://x","enabled":true}]}`)
	if err := b.Save(ctx, payload); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := b.Load(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("roundtrip distinto: %s", got)
	}
	v, err := b.Version(ctx)
	if err != nil || len(v) < 4 {
		t.Fatalf("version: %q %v", v, err)
	}

	raw, err := b.LoadLocks(ctx)
	if err != nil {
		t.Fatalf("loadlocks: %v", err)
	}
	_ = StatesToLimiter(raw)
	l := security.NewLimiter(2, time.Minute, time.Minute)
	for i := 0; i < 2; i++ {
		l.Fail("1.2.3.4")
	}
	snap := map[string]*security.LimiterState{"ip": l.Snapshot()}
	toSave, _ := StatesFromLimiter(snap)
	if err := b.SaveLocks(ctx, toSave); err != nil {
		t.Fatalf("savelocks: %v", err)
	}
	raw2, err := b.LoadLocks(ctx)
	if err != nil {
		t.Fatalf("loadlocks2: %v", err)
	}
	states2 := StatesToLimiter(raw2)
	ipSt, ok := states2["ip"]
	if !ok || ipSt.Entries["1.2.3.4"].Count != 2 {
		t.Fatalf("estado de bloqueos no persistido: %+v", states2)
	}

	if err := b.AppendAudit(ctx, "test_evento", "9.9.9.9", "usuario@test", "detalle"); err != nil {
		t.Fatalf("appendaudit: %v", err)
	}
}

func TestPgBackupRestoreRoundTrip(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	b, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer b.Close()

	cfgData := []byte(`{"admin_port":8001,"rules":[{"host":"bak.local","target":"http://dst","enabled":true}]}`)
	if err := b.Save(ctx, cfgData); err != nil {
		t.Fatalf("save config: %v", err)
	}

	l := security.NewLimiter(2, time.Minute, time.Minute)
	l.Fail("10.0.0.1")
	l.Fail("10.0.0.1")
	toSave, _ := StatesFromLimiter(map[string]*security.LimiterState{"ip": l.Snapshot()})
	if err := b.SaveLocks(ctx, toSave); err != nil {
		t.Fatalf("save locks: %v", err)
	}

	if err := b.AppendAudit(ctx, "bak_before", "5.5.5.5", "usr_bak", "antes del backup"); err != nil {
		t.Fatalf("appendaudit: %v", err)
	}

	data, err := b.SnapshotToJSON(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("json: %v", err)
	}
	if snap.Schema != BackupSchema {
		t.Fatalf("schema: %d", snap.Schema)
	}
	if snap.Counts["pxproxy_audit"] < 1 {
		t.Fatalf("audit vacio en backup")
	}

	if _, err := b.pool.Exec(ctx, `TRUNCATE pxproxy_locks, pxproxy_audit, pxproxy_config RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := b.pool.Exec(ctx, `SELECT setval(pg_get_serial_sequence('pxproxy_audit', 'id'), 1, false)`); err != nil {
		t.Fatalf("reset seq: %v", err)
	}

	done, err := b.RestoreFromJSON(ctx, data)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if done["pxproxy_config"] != 1 {
		t.Fatalf("config count tras restore: %d", done["pxproxy_config"])
	}
	if done["pxproxy_locks"] != 1 {
		t.Fatalf("locks count tras restore: %d", done["pxproxy_locks"])
	}
	if done["pxproxy_audit"] < 1 {
		t.Fatalf("audit count tras restore: %d", done["pxproxy_audit"])
	}

	gotCfg, err := b.Load(ctx)
	if err != nil {
		t.Fatalf("load post-restore: %v", err)
	}
	if string(gotCfg) != string(cfgData) {
		t.Fatalf("config distinta post-restore:\n  antes: %s\n  ahora: %s", cfgData, gotCfg)
	}

	gotLocks, err := b.LoadLocks(ctx)
	if err != nil {
		t.Fatalf("loadlocks post-restore: %v", err)
	}
	states := StatesToLimiter(gotLocks)
	ipSt, ok := states["ip"]
	if !ok || ipSt.Entries["10.0.0.1"].Count != 2 {
		t.Fatalf("locks no restaurados: %+v", states)
	}
}
