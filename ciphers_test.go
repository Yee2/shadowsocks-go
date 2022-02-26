package shadowsocks

import (
	"bytes"
	"errors"
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
	for _, m := range Supported() {
		t.Logf("test method:%s", m)
		RandStringRunes(password[:])
		buf.Reset()
		tunnel, err := NewTunnel(m, string(password[:]))
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

func TestAllUDP(t *testing.T) {
	var password [16]byte
	var data [4096]byte
	// 如果复用 decode，会出现 crypto/cipher: invalid buffer overlap
	var decode [4096]byte
	var encode [4096]byte
	for _, m := range Supported() {
		t.Logf("test method:%s", m)
		RandStringRunes(password[:])
		tunnel, err := NewTunnel(m, string(password[:]))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 10; i++ {
			size := rand.Intn(4000) + 1
			RandStringRunes(data[:size])
			n, err := tunnel.Pack(encode[:], data[:size])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tunnel.Unpack(decode[:], encode[:n]); err != nil {
				t.Fatal(err)
			}
			if string(decode[:size]) != string(data[:size]) {
				t.Failed()
			}
		}
	}

}

func BenchmarkAES256GCM(b *testing.B) {
	benchmarkSS(b, "aes-256-gcm")
}
func BenchmarkCC20(b *testing.B) {
	benchmarkSS(b, "chacha20-ietf-poly1305")
}
func BenchmarkSalsa20(b *testing.B) {
	benchmarkSS(b, "salsa20")
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
	tunnel, err := NewTunnel(m, string(password[:]))
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
