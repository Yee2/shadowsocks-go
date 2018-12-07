package shadowsocks

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewTunnel(t *testing.T) {
	password := "123456"
	testStr := "hello world!"
	strlen := len(testStr)
	bs := make([]byte, strlen)
	buffer := bytes.NewBuffer(make([]byte, 128))
	for _, method := range Supported() {
		buffer.Truncate(0)
		tunnel, err := NewTunnel(method, password)
		if err != nil {
			t.Fatal(err)
		}
		socks, err := tunnel.Shadow(buffer)
		if err != nil {
			t.Fatal(err)
		}
		n, err := socks.Write([]byte(testStr))
		if err != nil {
			t.Fatal(err)
		}
		if n != strlen {
			t.Fatal(errors.New("无法写入字符串"))
		}
		n, err = socks.Read(bs)
		if err != nil {
			t.Fatal(err)
		}
		if n != strlen {
			t.Fatal(errors.New("无法读取字符串"))
		}
		if string(bs) != testStr {
			t.Fatal(errors.New("读取字符串不正确"))
		}
	}
}
