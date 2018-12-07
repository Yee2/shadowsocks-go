package shadowsocks

import (
	"testing"
)

func TestAead_Pack(t *testing.T) {
	pipe, err := NewAES256GCM("Password")
	if err != nil {
		t.Fatal(err)
	}
	str := "wpafhjwpoiafh"
	var buffer [1024]byte
	n, err := pipe.Pack(buffer[:], []byte(str))
	if err != nil {
		t.Fatal(err)
	}
	n, err = pipe.Unpack(buffer[:0], buffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != str {
		t.Logf("%d\n",n)
		t.Fatal(string(buffer[:n]))
	}
}
