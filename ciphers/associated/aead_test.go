package associated

import (
	"github.com/Yee2/shadowsocks-go/ciphers/core"
	"testing"
)

func TestAEADImpl(t *testing.T) {
	var i interface{} = &aead{}
	if _, ok := i.(core.Tunnel); !ok {
		t.Failed()
	}
}
