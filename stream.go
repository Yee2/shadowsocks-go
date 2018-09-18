package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"crypto/rand"
	"errors"
)

// 实现 Tunnel 接口
type stream struct {
	block        cipher.Block
	IVLength     int
	NewDecrypter func(block cipher.Block, iv []byte) cipher.Stream
	NewEncrypter func(block cipher.Block, iv []byte) cipher.Stream
}

func (p *stream) Shadow(rw io.ReadWriter) (io.ReadWriter, error) {
	return &streamTunnel{model: p, ReadWriter: rw}, nil
}

func (p *stream) Pack(dst []byte, data []byte) error {
	if len(data) < p.IVLength {
		return errors.New("error")
	}
	p.NewEncrypter(p.block, data[:p.IVLength]).XORKeyStream(dst, data[p.IVLength:])
	return nil
}

func (p *stream) Unpack(dst []byte, data []byte) error {
	if len(data) < p.IVLength {
		return errors.New("error")
	}
	p.NewDecrypter(p.block, data[:p.IVLength]).XORKeyStream(dst, data[p.IVLength:])
	return nil
}

// 实现RW接口
type streamTunnel struct {
	model      *stream
	ReadWriter io.ReadWriter
	Decrypter  cipher.Stream
	Encrypter  cipher.Stream
}

func (c *streamTunnel) Read(p []byte) (n int, err error) {
	if c.Decrypter == nil {
		iv := make([]byte, c.model.IVLength)
		if _, err := io.ReadFull(c.ReadWriter, iv); err != nil {
			return 0, err
		}
		c.Decrypter = c.model.NewDecrypter(c.model.block, iv)
	}
	n, err = c.ReadWriter.Read(p)
	if err != nil {
		return
	}
	c.Decrypter.XORKeyStream(p[:n], p[:n])
	return
}
func (c *streamTunnel) Write(p []byte) (n int, err error) {
	if c.Encrypter == nil {
		iv := make([]byte, c.model.IVLength)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return 0, err
		}
		if _, err := c.ReadWriter.Write(iv); err != nil {
			return 0, nil
		}
		c.Encrypter = c.model.NewEncrypter(c.model.block, iv)
	}
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
