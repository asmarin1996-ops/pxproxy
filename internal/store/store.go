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

var ErrBackendUnavailable = errors.New("store: backend no disponible")

type ConfigBackend interface {
	Name() string
	Load(ctx context.Context) ([]byte, error)
	Save(ctx context.Context, data []byte) error
	Version(ctx context.Context) (string, error)
}

type LockBackend interface {
	SaveLocks(ctx context.Context, states map[string]json.RawMessage) error
	LoadLocks(ctx context.Context) (map[string]json.RawMessage, error)
}

type AuditBackend interface {
	AppendAudit(ctx context.Context, event, ip, user, detail string) error
}

type FileBackend struct {
	path string
}

func NewFileBackend(path string) *FileBackend {
	return &FileBackend{path: path}
}

func (f *FileBackend) Name() string { return "file" }

func (f *FileBackend) Load(ctx context.Context) ([]byte, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (f *FileBackend) Save(ctx context.Context, data []byte) error {
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

func (f *FileBackend) Version(ctx context.Context) (string, error) {
	st, err := os.Stat(f.path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("mtime:%d", st.ModTime().UnixNano()), nil
}

func BackupFile(path string, keep int) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return
	}
	bdir := filepath.Join(filepath.Dir(path), "backups")
	if err := os.MkdirAll(bdir, 0700); err != nil {
		return
	}
	name := filepath.Join(bdir, fmt.Sprintf("config-%s.json", time.Now().Format("20060102-150405")))
	_ = os.WriteFile(name, data, 0600)
	pruneBackups(bdir, keep)
}

func pruneBackups(bdir string, keep int) {
	if keep <= 0 {
		return
	}
	ents, err := os.ReadDir(bdir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		n := e.Name()
		if !e.IsDir() && filepath.Ext(n) == ".json" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for i := 0; i < len(names)-keep; i++ {
		_ = os.Remove(filepath.Join(bdir, names[i]))
	}
}
