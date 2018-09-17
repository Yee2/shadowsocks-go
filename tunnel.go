package shadowsocks

import (
	"io"
)

// 获取一个解密后的通道，读写将自动加密和解密
type Tunnel interface {
	Shadow(rw io.ReadWriter) (io.ReadWriter, error)
}
