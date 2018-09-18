package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// 实现 Tunnel 接口
type stream struct {
	block        cipher.Block
	IVLength     int
	NewDecrypter func(block cipher.Block, iv []byte) cipher.Stream
	NewEncrypter func(block cipher.Block, iv []byte) cipher.Stream
}

func (p *stream) Shadow(rw io.ReadWriter) (io.ReadWriter, error) {
	iv := make([]byte,p.IVLength)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	rw.Write(iv)
	streamEn := p.NewEncrypter(p.block, iv)
	return &streamTunnel{ReadWriter:rw,Encrypter: streamEn,initialize: func(c *streamTunnel) error{
		iv, err := GetIV(rw, p.IVLength)
		if err != nil {
			return err
		}
		c.Decrypter = p.NewDecrypter(p.block, iv)
		return nil
	},
	}, nil
}

// 实现RW接口
type streamTunnel struct {
	initialize func(*streamTunnel)error
	ReadWriter io.ReadWriter
	Decrypter  cipher.Stream
	Encrypter  cipher.Stream
}

func (c *streamTunnel) Read(p []byte) (n int, err error) {
	if c.Decrypter == nil{
		err = c.initialize(c)
		if err != nil{
			return 0,err
		}
	}
	n, err = c.ReadWriter.Read(p)
	if err != nil {
		return
	}
	c.Decrypter.XORKeyStream(p[:n], p[:n])
	return
}
func (c *streamTunnel) Write(p []byte) (n int, err error) {
	c.Encrypter.XORKeyStream(p, p)
	return c.ReadWriter.Write(p)
}

// 创建一个符合shadowsocks协议的AES-256-CFB加密通道
func NewAES256CFB(password string) (Tunnel, error) {
	key := kdf(password, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &stream{block: block, IVLength: 16, NewDecrypter: cipher.NewCFBDecrypter, NewEncrypter: cipher.NewCFBEncrypter}, nil
}
