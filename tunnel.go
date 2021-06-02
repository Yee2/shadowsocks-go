package shadowsocks

import (
	"io"
)

type Tunnel interface {
	// Shadow Get a decrypted channel, read and write will be automatically encrypted and decrypted
	Shadow(rw io.ReadWriteCloser) (io.ReadWriteCloser, error)
	Unpack(dst []byte, data []byte) (int, error)
	Pack(dst []byte, data []byte) (int, error)
}
