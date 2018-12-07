package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestM(t *testing.T) {
	key := "password"
	dir, err := ioutil.TempDir("", "fileProtector")
	if err != nil {
		t.Fatal(err)
	}
	origin := filepath.Join("test/fileProtector")
	encrypted := filepath.Join(dir, "fileProtector.encrypted")
	decrypted := filepath.Join(dir, "fileProtector.decrypted")

	err = encrypt("chacha20-ietf-poly1305", key, origin, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	err = decrypt("chacha20-ietf-poly1305", key, encrypted, decrypted)
	if err != nil {
		t.Fatal(err)
	}
	md5_origin, err := md5sum(origin)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("原文件md5:%s", md5_origin)
	md5_de, err := md5sum(decrypted)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("新文件md5:%s", md5_de)
	if md5_origin != md5_de {
		t.Fatalf("md5 校对失败")
	}
}
func md5sum(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%02X", h.Sum(nil)), nil
}
