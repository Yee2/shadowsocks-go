package stream

import (
	"shadowsocks/ciphers/core"
	"testing"
)

func TestStreamImpl(t *testing.T) {
	var i interface{} = &stream{}
	if _, ok := i.(core.Tunnel); !ok {
		t.Failed()
	}
}
