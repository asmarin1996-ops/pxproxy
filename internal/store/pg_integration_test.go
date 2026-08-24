package store

import (
	"context"
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
