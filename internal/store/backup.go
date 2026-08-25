package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const BackupSchema = 1

var ErrBadSnapshot = errors.New("store: fichero de backup no valido")

type TableSnapshot struct {
	Name  string            `json:"name"`
	Rows  []json.RawMessage `json:"rows"`
}

type Snapshot struct {
	Schema    int             `json:"schema"`
	CreatedAt time.Time       `json:"created_at"`
	Source    string          `json:"source"`
	Counts    map[string]int  `json:"counts"`
	Tables    []TableSnapshot `json:"tables"`
}

func (s *Snapshot) Table(name string) []json.RawMessage {
	for _, t := range s.Tables {
		if t.Name == name {
			return t.Rows
		}
	}
	return nil
}

func (b *PgBackend) SnapshotToJSON(ctx context.Context) ([]byte, error) {
	snap, err := b.Backup(ctx)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(snap, "", "  ")
}

func (b *PgBackend) RestoreFromJSON(ctx context.Context, data []byte) (map[string]int, error) {
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadSnapshot, err)
	}
	if snap.Schema != BackupSchema {
		return nil, fmt.Errorf("%w: schema %d soportado %d", ErrBadSnapshot, snap.Schema, BackupSchema)
	}
	if snap.Source != "postgres" || len(snap.Tables) == 0 {
		return nil, ErrBadSnapshot
	}
	return b.Restore(ctx, &snap)
}

func WriteBackupFile(dir string, data []byte) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	name := filepath.Join(dir, fmt.Sprintf("pxproxy-bd-%s.json", time.Now().Format("20060102-150405")))
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return "", err
	}
	return name, os.Rename(tmp, name)
}

func ListBackupFiles(dir string) []BackupInfo {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []BackupInfo
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || filepath.Ext(n) != ".json" {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, BackupInfo{File: n, Size: fi.Size(), Modified: fi.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Modified.After(out[j].Modified) })
	return out
}

type BackupInfo struct {
	File     string    `json:"file"`
	Size     int64     `json:"size_bytes"`
	Modified time.Time `json:"modified"`
}

func PruneBackupFiles(dir string, keep int) {
	if keep <= 0 {
		return
	}
	list := ListBackupFiles(dir)
	for i := keep; i < len(list); i++ {
		_ = os.Remove(filepath.Join(dir, list[i].File))
	}
}

func DeleteBackupFile(dir, name string) error {
	clean := filepath.Base(name)
	if clean == "." || clean == "/" || filepath.Ext(clean) != ".json" {
		return ErrBadSnapshot
	}
	return os.Remove(filepath.Join(dir, clean))
}
