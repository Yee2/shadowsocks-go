package ciphers

import (
	"bytes"
	"errors"
	"github.com/Yee2/shadowsocks-go"
	"io"
	"math/rand"
	"testing"
)

type rwc struct {
	io.ReadWriter
}

func (_ *rwc) Close() error {
	return nil
}

func TestAllPass(t *testing.T) {
	var res [1024]byte
	var k20 [1024 * 20]byte
	var password [16]byte
	var data [1000]byte
	buf := bytes.NewBuffer(k20[:0])
	for _, m := range shadowsocks.Supported() {
		RandStringRunes(password[:])
		buf.Reset()
		tunnel, err := shadowsocks.NewTunnel(m, string(password[:]))
		if err != nil {
			t.Fatal(err)
		}
		safeBuf, err := tunnel.Shadow(&rwc{ReadWriter: buf})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 10; i++ {
			RandStringRunes(data[:])
			if _, err := safeBuf.Write(data[:]); err != nil {
				t.Fatal(err)
			}
			n, err := safeBuf.Read(res[:])
			if errors.Is(err, io.EOF) {

			} else if err != nil {
				t.Fatalf("method:%s error:%s", m, err)
			}
			if string(res[:n]) != string(data[:]) {
				t.Failed()
			}
		}
		if err := safeBuf.Close(); err != nil {
			t.Failed()
		}
	}

}
func BenchmarkAES256GCM(b *testing.B) {
	benchmarkSS(b, "aes-256-gcm")
}
func BenchmarkCC20(b *testing.B) {
	benchmarkSS(b, "chacha20-ietf-poly1305")
}
func BenchmarkCC20Ietf(b *testing.B) {
	benchmarkSS(b, "chacha20")
}
func BenchmarkAES256CFB(b *testing.B) {
	benchmarkSS(b, "aes-256-cfb")
}

func benchmarkSS(t *testing.B, m string) {
	var res [1024]byte
	var k20 [1024 * 20]byte
	buf := bytes.NewBuffer(k20[:0])
	var password [16]byte
	var data [1000]byte
	RandStringRunes(data[:])
	t.ResetTimer()
	RandStringRunes(password[:])
	tunnel, err := shadowsocks.NewTunnel(m, string(password[:]))
	if err != nil {
		t.Fatal(err)
	}
	safeBuf, err := tunnel.Shadow(&rwc{ReadWriter: buf})
	if err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	for i := 0; i < t.N; i++ {
		if _, err := safeBuf.Write(data[:]); err != nil {
			t.Fatal(err)
		}
		_, err := safeBuf.Read(res[:])
		if errors.Is(err, io.EOF) {
		} else if err != nil {
			t.Fatalf("method:%s error:%s", m, err)
		}
	}
	if err := safeBuf.Close(); err != nil {
		t.Failed()
	}
}

var letterRunes = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(b []byte) {
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
}
