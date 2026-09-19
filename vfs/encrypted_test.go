package vfs

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptedVFSRoundTripAndSidecars(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "encrypted.sqlite")
	key := bytes.Repeat([]byte{0x42}, 64)
	name, encrypted, err := NewEncrypted(key)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Close()

	database, err := sql.Open("sqlite", "file:"+path+"?vfs="+name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`PRAGMA journal_mode=DELETE; CREATE TABLE secrets (value TEXT); INSERT INTO secrets VALUES ('rollback-secret')`); err != nil {
		t.Fatal(err)
	}
	transaction, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`UPDATE secrets SET value = 'journal-secret'`); err != nil {
		t.Fatal(err)
	}
	assertEncryptedFile(t, path+"-journal", "journal-secret", "rollback-secret")
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	assertEncryptedFile(t, path, "SQLite format 3", "rollback-secret")

	database, err = sql.Open("sqlite", "file:"+path+"?vfs="+name)
	if err != nil {
		t.Fatal(err)
	}
	var value string
	if err := database.QueryRow(`SELECT value FROM secrets`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "rollback-secret" {
		t.Fatalf("value = %q", value)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptedVFSWALIsEncrypted(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "wal.sqlite")
	name, encrypted, err := NewEncrypted(bytes.Repeat([]byte{0x24}, 64))
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Close()

	database, err := sql.Open("sqlite", "file:"+path+"?vfs="+name)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`PRAGMA journal_mode=WAL; CREATE TABLE secrets (value TEXT); INSERT INTO secrets VALUES ('wal-secret-value')`); err != nil {
		t.Fatal(err)
	}
	assertEncryptedFile(t, path+"-wal", "wal-secret-value", "SQLite format 3")
}

func TestEncryptedVFSRecoversUncheckpointedWAL(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.sqlite")
	recoveryPath := filepath.Join(directory, "recovery.sqlite")
	name, encrypted, err := NewEncrypted(bytes.Repeat([]byte{0x36}, 64))
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Close()

	database, err := sql.Open("sqlite", "file:"+sourcePath+"?vfs="+name)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE secrets (value TEXT); PRAGMA wal_checkpoint(TRUNCATE); INSERT INTO secrets VALUES ('wal-recovery-secret')`); err != nil {
		t.Fatal(err)
	}
	copyFile(t, sourcePath, recoveryPath)
	copyFile(t, sourcePath+"-wal", recoveryPath+"-wal")

	recovered, err := sql.Open("sqlite", "file:"+recoveryPath+"?vfs="+name)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	var value string
	if err := recovered.QueryRow(`SELECT value FROM secrets`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "wal-recovery-secret" {
		t.Fatalf("value = %q", value)
	}
}

func TestEncryptedVFSRejectsWrongKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrong-key.sqlite")
	name, encrypted, err := NewEncrypted(bytes.Repeat([]byte{0x11}, 64))
	if err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", "file:"+path+"?vfs="+name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE secrets (value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.Close(); err != nil {
		t.Fatal(err)
	}

	wrongName, wrong, err := NewEncrypted(bytes.Repeat([]byte{0x22}, 64))
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	database, err = sql.Open("sqlite", "file:"+path+"?vfs="+wrongName)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Ping(); err == nil {
		t.Fatal("opening with the wrong encryption key succeeded")
	}
}

func TestNewEncryptedRejectsInvalidKey(t *testing.T) {
	if _, _, err := NewEncrypted([]byte("too short")); err == nil {
		t.Fatal("short encryption key was accepted")
	}
}

func assertEncryptedFile(t *testing.T, path string, plaintext ...string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range plaintext {
		if bytes.Contains(data, []byte(value)) {
			t.Fatalf("%s contains plaintext %q", filepath.Base(path), value)
		}
	}
	if strings.TrimSpace(string(data)) == "" {
		t.Fatalf("%s is empty", filepath.Base(path))
	}
}

func copyFile(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
