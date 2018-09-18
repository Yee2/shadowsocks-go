package shadowsocks

import (
	"io"
)

type Tunnel interface {
	// 获取一个解密后的通道，读写将自动加密和解密
	Shadow(rw io.ReadWriter) (io.ReadWriter, error)
	//解包数据
	// 参考 https://shadowsocks.org/en/spec/AEAD-Ciphers.html
	Unpack(dst []byte,data[]byte)error
	// 打包数据
	Pack(dst []byte,data[]byte)error
}
