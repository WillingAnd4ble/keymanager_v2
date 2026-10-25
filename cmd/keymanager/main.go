// Command keymanager is the CLI entry point of the encrypted key manager.
package main

import (
	"fmt"
	"golang.org/x/term"
	"keymanager/internal/crypto"
	"keymanager/internal/store"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	dir, err := os.UserConfigDir()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	dir = filepath.Join(dir, "keymanager")
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	path := filepath.Join(dir, "vault.json")
	vault, err := store.Load(path)
	if err != nil {
		fmt.Println("load error:", err)
		os.Exit(1)
	}
	fmt.Print("Password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Println("password error:", err)
		os.Exit(1)
	}
	key := crypto.DeriveKey(password, vault.Salt)
	if len(vault.Check) == 0 {
		vault.Check, err = crypto.Encrypt(key, []byte("ok"))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		vault.Save(path)
	}
	if _, err := crypto.Decrypt(key, vault.Check); err != nil {
		fmt.Println("wrong password")
		os.Exit(1)
	}
	fmt.Println("unlocked")

	if len(os.Args) < 2 {
		fmt.Println("usage: keymanager add|get|list")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "list":
		vault.List()
	case "add":
		// os.Args[2] = name, os.Args[3] = secret
		if len(os.Args) < 4 {
			fmt.Println("usage: add <name> <secret>")
			os.Exit(1)
		}
		ct, err := crypto.Encrypt(key, []byte(os.Args[3]))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if err := vault.Add(store.Entry{Name: os.Args[2], Value: ct, CreatedAt: time.Now()}); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if err := vault.Save(path); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("saved")

	case "get":
		// os.Args[2] = name
		if len(os.Args) < 3 {
			fmt.Println("usage: get <name>")
			os.Exit(1)
		}

		ct, ok := vault.Get(os.Args[2])
		if !ok {
			fmt.Println("not found")
			os.Exit(1)
		}
		plain, err := crypto.Decrypt(key, ct.Value)
		if err != nil {
			fmt.Println("wrong password or corrupted data")
			os.Exit(1)
		}
		fmt.Println(string(plain))

	}
}
