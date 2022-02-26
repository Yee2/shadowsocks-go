package associated

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"github.com/Yee2/shadowsocks-go/ciphers/core"
	"golang.org/x/crypto/hkdf"
	"io"
	"sync"
)

const MaxPayload = 0x3FFF

var buffers = &sync.Pool{New: func() interface{} {
	return bytes.NewBuffer(nil)
}}

const cacheSize = MaxPayload + 1024

var chunk = &sync.Pool{New: func() interface{} {
	return make([]byte, cacheSize)
}}

var zero [128]byte

type aead struct {
	key []byte
	KeySize,
	SaltSize,
	NonceSize,
	TagSize int
	NewAEAD    func(key []byte) (cipher.AEAD, error)
	subKeyPool *sync.Pool
}

func (p *aead) Shadow(rw io.ReadWriteCloser) (_ io.ReadWriteCloser, e error) {
	return &aeadTunnel{
		model:  p,
		pipe:   rw,
		RNonce: make([]byte, p.NonceSize),
		WNonce: make([]byte, p.NonceSize),
		cache:  buffers.Get().(*bytes.Buffer),
	}, nil
}
func (p *aead) Unpack(dst []byte, data []byte) (int, error) {
	if len(data) < p.SaltSize {
		return 0, fmt.Errorf("the ciphertext length is too short(%d bytes)", len(data))
	}
	subKey := p.subKeyPool.Get().([]byte)
	defer p.subKeyPool.Put(subKey)
	hkdfSHA1(p.key, data[:p.SaltSize], []byte("ss-subkey"), subKey)
	AEAD, err := p.NewAEAD(subKey)
	if err != nil {
		return 0, err
	}
	d, err := AEAD.Open(dst, zero[:p.NonceSize], data[p.SaltSize:], nil)
	return len(d), err
}
func (p *aead) Pack(dst []byte, data []byte) (int, error) {
	if _, err := io.ReadFull(rand.Reader, dst[:p.SaltSize]); err != nil {
		return 0, fmt.Errorf("failed to generate a salt:%w size:%d", err, p.SaltSize)
	}
	subKey := p.subKeyPool.Get().([]byte)
	defer p.subKeyPool.Put(subKey)
	hkdfSHA1(p.key, dst[:p.SaltSize], []byte("ss-subkey"), subKey)
	AEAD, err := p.NewAEAD(subKey)
	if err != nil {
		return 0, err
	}
	result := AEAD.Seal(nil, zero[:p.NonceSize], data, nil)
	copy(dst[p.SaltSize:], result)
	return len(result) + p.SaltSize, nil
}

type aeadTunnel struct {
	pipe   io.ReadWriteCloser
	model  *aead
	RAEAD  cipher.AEAD
	WAEAD  cipher.AEAD
	RNonce []byte //这是一个小端模式的计算器
	WNonce []byte //这是一个小端模式的计算器
	cache  *bytes.Buffer
	closed bool
}

func (c *aeadTunnel) Close() error {
	if c.closed {
		return fmt.Errorf("closed")
	}
	buffers.Put(c.cache)
	c.cache = nil
	c.closed = true
	return core.ClosedErr
}

func (c *aeadTunnel) Open(dst, cipherText []byte) ([]byte, error) {
	defer func() {
		increment(c.RNonce)
	}()
	return c.RAEAD.Open(dst, c.RNonce, cipherText, nil)
}

func (c *aeadTunnel) Seal(dst, plaintext []byte) []byte {
	defer func() {
		increment(c.WNonce)
	}()
	return c.WAEAD.Seal(dst, c.WNonce, plaintext, nil)
}

func (c *aeadTunnel) nextChunk() (err error) {
	data := chunk.Get().([]byte)[0 : 2+c.RAEAD.Overhead()]
	defer chunk.Put(data)
	if _, err = io.ReadFull(c.pipe, data); err != nil {
		return err
	}
	head, err := c.Open(data[:0], data)
	if err != nil {
		return fmt.Errorf("decrypted message failure(block:%d):%w ", len(data), err)
	} else if len(head) != 2 {
		panic("data length is abnormal")
	}
	size := (int(head[0])<<8 + int(head[1])) & MaxPayload

	_, err = io.ReadFull(c.pipe, data[0:size+c.RAEAD.Overhead()])
	if err != nil {
		return
	}
	payload, err := c.Open(data[:0], data[0:size+c.RAEAD.Overhead()])
	if err != nil {
		return
	}
	_, err = c.cache.Write(payload)
	return
}
func (c *aeadTunnel) Read(p []byte) (n int, err error) {
	if c.RAEAD == nil {
		// init reader
		salt := make([]byte, c.model.SaltSize)
		if _, err := io.ReadFull(c.pipe, salt); err != nil {
			return 0, fmt.Errorf("failed to read the salt:%w size:%d", err, c.model.SaltSize)
		}
		subKey := make([]byte, c.model.KeySize)
		hkdfSHA1(c.model.key, salt, []byte("ss-subkey"), subKey)
		c.RAEAD, err = c.model.NewAEAD(subKey)
		if err != nil {
			return 0, fmt.Errorf("decryptor init error:%w", err)
		}
	}

	for {
		nn, err := c.cache.Read(p)
		n += nn
		if err != nil && !errors.Is(err, io.EOF) {
			return n, err
		} else if len(p) == nn {
			return n, err
		}
		p = p[nn:]
		err = c.nextChunk()
		if err != nil {
			return n, err
		}
	}
}
func (c *aeadTunnel) Write(p []byte) (n int, err error) {
	if c.WAEAD == nil {
		salt := make([]byte, c.model.SaltSize)
		if _, err = io.ReadFull(rand.Reader, salt); err != nil {
			return 0, fmt.Errorf("failed to make a new salt:%w size:%d", err, c.model.SaltSize)
		} else if n, err = c.pipe.Write(salt); err != nil {
			return 0, fmt.Errorf("send salt bytes error:%w", err)
		} else if n != c.model.SaltSize {
			panic(fmt.Errorf("runtime error"))
		}
		key := make([]byte, c.model.KeySize)
		hkdfSHA1(c.model.key, salt, []byte("ss-subkey"), key)
		if c.WAEAD, err = c.model.NewAEAD(key); err != nil {
			return 0, err
		}
	}

	var end, nn int
	size := len(p)
	for i := 0; i*MaxPayload < size; i++ {
		end = (i + 1) * MaxPayload
		if end > len(p) {
			end = len(p)
		}
		nn, err = c.write(p[i*MaxPayload : end])
		n += nn
		if err != nil {
			return
		}
	}
	return n, nil
}
func (c *aeadTunnel) write(p []byte) (n int, err error) {
	if len(p) > MaxPayload {
		return 0, errors.New("超过限制")
	}
	size := len(p)
	data := chunk.Get().([]byte)
	defer chunk.Put(data)
	p1 := c.Seal(data[:0], []byte{byte(size >> 8), byte(size)})
	p2 := c.Seal(p1[len(p1):], p)
	_, err = c.pipe.Write(p1)
	if err != nil {
		return n, err
	}
	_, err = c.pipe.Write(p2)
	if err != nil {
		return n, err
	}
	return size, nil
}

// from https://github.com/shadowsocks/go-shadowsocks2/blob/ef4b562095a69750509f82d3f82fc8e6dad50c6e/shadowaead/stream.go
// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

func hkdfSHA1(secret, salt, info, outkey []byte) {
	r := hkdf.New(sha1.New, secret, salt, info)
	if _, err := io.ReadFull(r, outkey); err != nil {
		panic(err) // should never happen
	}
}
