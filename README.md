# Go Key Manager

An encrypted key management tool, written to learn Go.

## Layout

```
cmd/keymanager/   CLI entry point (package main)
internal/crypto/  encryption / decryption / key derivation
internal/store/   on-disk persistence of encrypted entries
```

## Run

```sh
go install ./cmd/keymanager
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
keymanger ......
```