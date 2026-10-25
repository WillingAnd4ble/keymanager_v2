// Package crypto handles encryption and decryption of secrets.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"io"
)

// Phase 2:
// TODO 8:  derive a 32-byte key from a password: golang.org/x/crypto/argon2 (argon2.IDKey), add it with `go get`.
//          Random salt from crypto/rand (never math/rand).
// TODO 9:  Encrypt(key, plaintext): crypto/aes + cipher.NewGCM.
//          Fresh random nonce for every call; return nonce+ciphertext as one []byte.
// TODO 10: Decrypt(key, data): split off the nonce, then gcm.Open.
//          Check the input length first so short input can't panic.
//          Wrong key or tampered data must return an error.
// TODO 11: crypto_test.go: round trip, wrong key, tampered ciphertext,
//          same plaintext encrypts to different outputs.
//
// Phase 3:
// TODO 14: read the master password without echo (golang.org/x/term, term.ReadPassword).
//          Never take it as a command-line argument (shell history).
//
// Phase 5 (optional):
// TODO 17: zero key/password bytes after use; learn why that is hard in Go.

// Encrypt seals plainText with AES-256-GCM and returns the (nonce, ciphertext)
// pair. secretKey must be 16, 24, or 32 bytes long.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("the key is too short or too long")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("read random nonce: %w", err)
	}

	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt reverses Encrypt and returns the plaintext.
func Decrypt(key, data []byte) ([]byte, error) {

	if len(key) != 32 {
		return nil, fmt.Errorf("the key is too short or too long")
	}

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	n := aesgcm.NonceSize()
	if len(data) < n {
		return nil, errors.New("ciphertext too short")
	}

	nonce := data[:n]
	ct := data[n:]

	plaintext, err := aesgcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("aesgcm.Open: %w", err)
	}
	return plaintext, nil
}

func NewSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func DeriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}
