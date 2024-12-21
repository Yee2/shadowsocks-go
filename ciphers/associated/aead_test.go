package associated

import (
	"shadowsocks/ciphers/core"
	"testing"
)

func TestAEADImpl(t *testing.T) {
	var i interface{} = &aead{}
	if _, ok := i.(core.Tunnel); !ok {
		t.Failed()
	}
}
