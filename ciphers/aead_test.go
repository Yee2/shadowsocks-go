package ciphers

import (
	"github.com/Yee2/shadowsocks-go"
	"testing"
)

func TestAEADImpl(t *testing.T) {
	var i interface{} = &aead{}
	if _, ok := i.(shadowsocks.Tunnel); !ok {
		t.Failed()
	}
}
