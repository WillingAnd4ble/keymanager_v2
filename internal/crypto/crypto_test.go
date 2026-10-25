package crypto

import (
	"bytes"
	"testing"
)

func testKey(b byte) []byte {
	return bytes.Repeat([]byte{b}, 32)
}

func TestRoundTrip(t *testing.T) {

	key := testKey(1)
	plain := []byte("secret")

	ct, err := Encrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("got %s, want %s", got, plain)
	}
}

func TestWrongKey(t *testing.T) {
	ct, _ := Encrypt(testKey(1), []byte("secret"))
	if _, err := Decrypt(testKey(2), ct); err == nil {
		t.Error("want error with wrong key")
	}
}

func TestTampered(t *testing.T) {
	key := testKey(1)
	ct, _ := Encrypt(key, []byte("secret"))
	ct[len(ct)-1] ^= 1 // flip one bit
	if _, err := Decrypt(key, ct); err == nil {
		t.Error("want error for tampered data")
	}
}

func TestDifferentOutputs(t *testing.T) {
	key := testKey(1)
	a, _ := Encrypt(key, []byte("secret"))
	b, _ := Encrypt(key, []byte("secret"))
	if bytes.Equal(a, b) {
		t.Error("same plaintext produced identical ciphertext")
	}
}

func TestShortInput(t *testing.T) {
	if _, err := Decrypt(testKey(1), []byte{1, 2}); err == nil {
		t.Error("want error for short input")
	}
}

func TestBadKeyLength(t *testing.T) {
	if _, err := Encrypt([]byte("short"), []byte("x")); err == nil {
		t.Error("want error for bad key length")
	}
}

func TestDeriveKey(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	a := DeriveKey([]byte("pw"), salt)
	b := DeriveKey([]byte("pw"), salt)
	if len(a) != 32 || !bytes.Equal(a, b) {
		t.Error("same password and salt must give the same 32-byte key")
	}

	salt2, _ := NewSalt()
	if bytes.Equal(a, DeriveKey([]byte("pw"), salt2)) {
		t.Error("different salt must give a different key")
	}
}
