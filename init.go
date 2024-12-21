package shadowsocks

import (
	"shadowsocks/ciphers/associated"
	"shadowsocks/ciphers/stream"
)

func init() {
	_ = Register(associated.AES128GCM)
	_ = Register(associated.AES192GCM)
	_ = Register(associated.AES256GCM)
	_ = Register(associated.Chacha20IetfPoly1305)
	_ = Register(stream.AES128CFB)
	_ = Register(stream.AES192CFB)
	_ = Register(stream.AES256CFB)
	_ = Register(stream.AES128CTR)
	_ = Register(stream.AES192CTR)
	_ = Register(stream.AES256CTR)
	_ = Register(stream.Camellia128CFB)
	_ = Register(stream.Camellia192CFB)
	_ = Register(stream.Camellia256CFB)
	_ = Register(stream.Salsa20)
}
