package stream

import (
	"github.com/Yee2/shadowsocks-go/ciphers/core"
	"testing"
)

func TestStreamImpl(t *testing.T) {
	var i interface{} = &stream{}
	if _, ok := i.(core.Tunnel); !ok {
		t.Failed()
	}
}
