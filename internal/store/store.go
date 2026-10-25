// Package store persists encrypted entries on disk.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"keymanager/internal/crypto"
	"os"
	"time"
)

// Phase 1 (no encryption yet, treat values as opaque bytes):
// TODO 2: define Vault struct holding the entries ([]Entry or map[string]Entry - pick one, be ready to explain why).
// TODO 3: methods on Vault: Add, Get, List, Delete.
//         Pointer receivers for the mutating ones, return error (no panics).
//         Sentinel errors: ErrNotFound, ErrAlreadyExists (check later with errors.Is).
//         List returns the names sorted.
// TODO 4: Save(path) / Load(path) with encoding/json + os.ReadFile / os.WriteFile.
//         Load on a missing file (errors.Is(err, os.ErrNotExist)) returns an empty vault.
//         File permissions 0600.
// >>> It wont do it, the path will be hardcoded// TODO 5: vault location via os.UserConfigDir(); create the dir with os.MkdirAll, mode 0700.
// TODO 6: safe saving: write to a temp file in the same dir, then os.Rename over the real file.
// TODO 7: store_test.go: table-driven tests with t.TempDir()
//         (add, duplicate add, get missing, delete, save/load round trip).
//
// Phase 3 (after internal/crypto works):
// TODO 12: store the salt in the vault file (file-level header or inside Vault).
// TODO 13: encrypt Entry.Value before saving, decrypt on Get.
//          Decide: inside store, or in a layer that calls both store and crypto?
// TODO 19 (optional): add a version field to the vault file format.

type Entry struct {
	Name                 string
	Value                []byte
	CreatedAt, UpdatedAt time.Time
}
type Vault struct {
	Entries map[string]Entry
	Salt    []byte
	Check   []byte
}

func (v *Vault) Add(entry Entry) error {
	if _, ok := v.Entries[entry.Name]; ok {
		return errors.New("entry exists")
	}
	v.Entries[entry.Name] = entry
	return nil
}

func (v *Vault) Get(name string) (Entry, bool) {
	entry, ok := v.Entries[name]
	return entry, ok
}
func (v *Vault) List() {
	for name, _ := range v.Entries {
		fmt.Println(name)
	}
}
func (v *Vault) Delete(name string) {
	delete(v.Entries, name)
}

func (v *Vault) Save(path string) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func Load(path string) (*Vault, error) {
	data, err := os.ReadFile(path)

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			salt, err := crypto.NewSalt()
			if err != nil {
				return nil, err
			}
			return &Vault{Entries: map[string]Entry{}, Salt: salt}, nil
		}
		return nil, err
	}

	var v Vault
	err = json.Unmarshal(data, &v)
	if err != nil {
		return nil, err
	}
	return &v, nil
}
