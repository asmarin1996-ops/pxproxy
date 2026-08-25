package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWriteBackupFile(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"schema":1,"test":true}`)

	name, err := WriteBackupFile(dir, data)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("content mismatch")
	}

	base := filepath.Base(name)
	if !strings.HasPrefix(base, "pxproxy-bd-") || filepath.Ext(base) != ".json" {
		t.Fatalf("filename: %q", base)
	}
}

func TestListBackupFiles(t *testing.T) {
	dir := t.TempDir()
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		name, _ := WriteBackupFile(dir, []byte(`{"n":`+string(rune('0'+i))+`}`))
		seen[filepath.Base(name)] = true
		time.Sleep(2 * time.Millisecond)
	}

	list := ListBackupFiles(dir)
	if len(list) < 3 {
		t.Fatalf("list: got %d, want >= 3", len(list))
	}

	for i := 1; i < len(list); i++ {
		if list[i-1].Modified.Before(list[i].Modified) {
			t.Fatal("list should be sorted newest first")
		}
	}
}

func TestPruneBackupFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		WriteBackupFile(dir, []byte(`{}`))
		time.Sleep(2 * time.Millisecond)
	}

	PruneBackupFiles(dir, 2)

	list := ListBackupFiles(dir)
	if len(list) != 2 {
		t.Fatalf("after prune: got %d, want 2", len(list))
	}
}

func TestDeleteBackupFile(t *testing.T) {
	dir := t.TempDir()
	name, _ := WriteBackupFile(dir, []byte(`{"test":true}`))
	base := filepath.Base(name)

	if err := DeleteBackupFile(dir, base); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, base)); !os.IsNotExist(err) {
		t.Fatal("file should not exist after delete")
	}
}

func TestDeleteBackupPathTraversal(t *testing.T) {
	dir := t.TempDir()
	err := DeleteBackupFile(dir, "../../etc/passwd")
	if err == nil {
		t.Fatal("should reject path traversal")
	}
}

func TestDeleteBackupBadExtension(t *testing.T) {
	dir := t.TempDir()
	err := DeleteBackupFile(dir, "test.txt")
	if err == nil {
		t.Fatal("should reject non-json extension")
	}
}

func TestPruneBackupKeepZero(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		WriteBackupFile(dir, []byte(`{}`))
		time.Sleep(2 * time.Millisecond)
	}
	PruneBackupFiles(dir, 0)
	list := ListBackupFiles(dir)
	if len(list) != 3 {
		t.Fatalf("keep=0 should keep all: got %d", len(list))
	}
}

func TestWriteBackupFileAtomic(t *testing.T) {
	dir := t.TempDir()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				WriteBackupFile(dir, []byte(`{"n":`+string(rune('0'+n))+`}`))
				time.Sleep(3 * time.Millisecond)
			}
		}(i)
	}
	wg.Wait()

	list := ListBackupFiles(dir)
	if len(list) < 1 {
		t.Fatalf("concurrent writes: got 0 files")
	}

	for _, fi := range list {
		data, err := os.ReadFile(filepath.Join(dir, fi.File))
		if err != nil {
			t.Fatalf("read %s: %v", fi.File, err)
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("corrupt file %s: %v", fi.File, err)
		}
	}
}
