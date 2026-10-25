package store

import (
	"bytes"
	"path/filepath"
	"testing"
)

func newVault() *Vault { return &Vault{Entries: map[string]Entry{}} }

func TestAddGetDelete(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T, v *Vault)
	}{
		{"add", func(t *testing.T, v *Vault) {
			if err := v.Add(Entry{Name: "a"}); err != nil {
				t.Fatal(err)
			}
			if _, ok := v.Get("a"); !ok {
				t.Error("want a")
			}
		}},
		{"duplicate add", func(t *testing.T, v *Vault) {
			v.Add(Entry{Name: "a"})
			if err := v.Add(Entry{Name: "a"}); err == nil {
				t.Error("want error")
			}
		}},
		{"get missing", func(t *testing.T, v *Vault) {
			if _, ok := v.Get("x"); ok {
				t.Error("want not found")
			}
		}},
		{"delete", func(t *testing.T, v *Vault) {
			v.Add(Entry{Name: "a"})
			v.Delete("a")
			if _, ok := v.Get("a"); ok {
				t.Error("want deleted")
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, newVault()) })
	}
}

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	v := newVault()
	v.Add(Entry{Name: "a", Value: []byte("secret")})
	if err := v.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := got.Get("a")
	if !ok || string(e.Value) != "secret" {
		t.Errorf("got %+v", e)
	}
}

func TestLoadMissing(t *testing.T) {
	v, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || len(v.Entries) != 0 {
		t.Errorf("want empty vault, got %v %v", v, err)
	}
}
func TestSaltPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")

	v1, err := Load(path) // missing file, creates a salt
	if err != nil {
		t.Fatal(err)
	}
	if err := v1.Save(path); err != nil {
		t.Fatal(err)
	}

	v2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(v2.Salt) != 16 || !bytes.Equal(v1.Salt, v2.Salt) {
		t.Error("salt not preserved")
	}
}
