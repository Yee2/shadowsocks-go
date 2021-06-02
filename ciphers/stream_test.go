package ciphers

import (
	"github.com/Yee2/shadowsocks-go"
	"testing"
)

func TestStreamImpl(t *testing.T) {
	var i interface{} = &stream{}
	if _, ok := i.(shadowsocks.Tunnel); !ok {
		t.Failed()
	}
}
