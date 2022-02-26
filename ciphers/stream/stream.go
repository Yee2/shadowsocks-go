package stream

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/Yee2/shadowsocks-go/ciphers/core"
	"io"
)

// 实现 Tunnel 接口
type stream struct {
	block        cipher.Block
	IVLength     int
	NewDecryptor func(block cipher.Block, iv []byte) cipher.Stream
	NewEncryptor func(block cipher.Block, iv []byte) cipher.Stream
}

func (p *stream) Shadow(rw io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	return &streamTunnel{model: p, pipe: rw}, nil
}

func (p *stream) Pack(dst []byte, data []byte) (int, error) {

	if _, err := io.ReadFull(rand.Reader, dst[:p.IVLength]); err != nil {
		return 0, err
	}

	p.NewEncryptor(p.block, dst[:p.IVLength]).XORKeyStream(dst[p.IVLength:], data)
	return len(data) + p.IVLength, nil
}

func (p *stream) Unpack(dst []byte, data []byte) (int, error) {
	if len(data) < p.IVLength {
		return 0, errors.New("data length less than IV length")
	}
	p.NewDecryptor(p.block, data[:p.IVLength]).XORKeyStream(dst, data[p.IVLength:])
	return len(data) - p.IVLength, nil
}

// 实现RW接口
type streamTunnel struct {
	model     *stream
	pipe      io.ReadWriteCloser
	decryptor cipher.Stream
	encryptor cipher.Stream
	closed    bool
}

func (c *streamTunnel) Close() error {
	if c.closed {
		return core.ClosedErr
	}
	return c.pipe.Close()
}

func (c *streamTunnel) Read(p []byte) (n int, err error) {
	if c.decryptor == nil {
		iv := make([]byte, c.model.IVLength)
		if _, err := io.ReadFull(c.pipe, iv); err != nil {
			return 0, fmt.Errorf("init Decrypter failed,read VI error:%w", err)
		}
		c.decryptor = c.model.NewDecryptor(c.model.block, iv)
	}
	n, err = c.pipe.Read(p)
	if err != nil {
		return n, fmt.Errorf("read data from stream error:%w", err)
	}
	c.decryptor.XORKeyStream(p[:n], p[:n])
	return
}
func (c *streamTunnel) Write(p []byte) (n int, err error) {
	if c.closed {
		return 0, core.ClosedErr
	}
	if c.encryptor == nil {
		iv := make([]byte, c.model.IVLength)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return 0, fmt.Errorf("init Encrypter failed,read VI error:%w", err)
		}
		if _, err := c.pipe.Write(iv); err != nil {
			return 0, fmt.Errorf("init Encrypter failed,generate IV error:%w", err)
		}
		c.encryptor = c.model.NewEncryptor(c.model.block, iv)
	}
	c.encryptor.XORKeyStream(p, p)
	return c.pipe.Write(p)
}
