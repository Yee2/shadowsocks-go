package shadowsocks

import (
	"github.com/Yee2/shadowsocks-go/ciphers/associated"
	"github.com/Yee2/shadowsocks-go/ciphers/stream"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().Unix())
	Register(associated.AES128GCM)
	Register(associated.AES192GCM)
	Register(associated.AES256GCM)
	Register(associated.Chacha20IetfPoly1305)
	Register(stream.AES128CFB)
	Register(stream.AES192CFB)
	Register(stream.AES256CFB)
	Register(stream.AES128CTR)
	Register(stream.AES192CTR)
	Register(stream.AES256CTR)
	Register(stream.Camellia128CFB)
	Register(stream.Camellia192CFB)
	Register(stream.Camellia256CFB)
	Register(stream.Salsa20)
}
