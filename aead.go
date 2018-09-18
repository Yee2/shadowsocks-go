package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"errors"
	"golang.org/x/crypto/hkdf"
	"io"
	"crypto/rand"
)

const MaxPayload = 0x3FFF
var zero [128]byte
type aead struct {
	key []byte
	KeySize,
	SaltSize,
	NonceSize,
	TagSize int
	NewAEAD func(key []byte) (cipher.AEAD, error)
}

func (p *aead) Shadow(rw io.ReadWriter) (_ io.ReadWriter, e error) {
	return &aeadTunnel{
		model:      p,
		ReadWriter: rw,
		RNonce:     make([]byte, p.NonceSize),
		WNonce:     make([]byte, p.NonceSize),
		cache:      make([]byte, 0),
	}, nil
}
func (p *aead) Unpack(dst []byte, data []byte) error {
	if len(data)<p.SaltSize{
		return errors.New("error")
	}
	subKey := make([]byte, p.KeySize)
	hkdfSHA1(p.key, data[:p.SaltSize], []byte("ss-subkey"), subKey)
	AEAD,err := p.NewAEAD(subKey)
	if err != nil{
		return err
	}
	AEAD.Open(dst,zero[:p.NonceSize],data[p.SaltSize:],nil)
	return nil
}
func (p *aead) Pack(dst []byte, data []byte) error {
	if len(data)<p.SaltSize{
		return errors.New("error")
	}
	subKey := make([]byte, p.KeySize)
	hkdfSHA1(p.key, data[:p.SaltSize], []byte("ss-subkey"), subKey)
	AEAD,err := p.NewAEAD(subKey)
	if err != nil{
		return err
	}
	AEAD.Seal(dst,zero[:p.NonceSize],data[p.SaltSize:],nil)
	return nil
}
type aeadTunnel struct {
	io.ReadWriter
	model  *aead
	RAEAD  cipher.AEAD
	WAEAD  cipher.AEAD
	RNonce []byte //这是一个小端模式的计算器
	WNonce []byte //这是一个小端模式的计算器
	buffer []byte
	cache  []byte
	subKey []byte
}

func (c *aeadTunnel) Open(dst, ciphertext []byte) ([]byte, error) {
	defer func() {
		increment(c.RNonce)
	}()
	return c.RAEAD.Open(dst, c.RNonce, ciphertext, nil)
}

func (c *aeadTunnel) Seal(dst, plaintext []byte) []byte {
	defer func() {
		increment(c.WNonce)
	}()
	return c.WAEAD.Seal(dst, c.WNonce, plaintext, nil)
}

func (c *aeadTunnel) Read(p []byte) (n int, err error) {
	if c.RAEAD == nil {
		salt := make([]byte, c.model.SaltSize)
		_, err := io.ReadFull(c.ReadWriter, salt)
		if err != nil {
			return 0, err
		}
		subKey := make([]byte, c.model.KeySize)
		hkdfSHA1(c.model.key, salt, []byte("ss-subkey"), subKey)
		c.RAEAD, err = c.model.NewAEAD(subKey)
		if err != nil {
			return 0, err
		}
		if c.buffer == nil {
			c.buffer = make([]byte, 2+c.RAEAD.Overhead()+MaxPayload+c.RAEAD.Overhead())
		}
	}

	if len(c.cache) > 0 {
		n = copy(p, c.cache)
		c.cache = c.cache[n:]
		if n == len(p) {
			return n, nil
		}
	}
	// 貌似 shadowsocks 协议里面 tag长度 对应的就是 AEAD.Overhead()，查看 gcm.go 源码可知
	raw := c.buffer[0 : 2+c.RAEAD.Overhead()]
	_, err = io.ReadFull(c.ReadWriter, raw)
	if err != nil {
		return
	}

	_, err = c.Open(raw[:0], raw)
	if err != nil {
		return
	}

	size := (int(raw[0])<<8 + int(raw[1])) & MaxPayload
	raw = c.buffer[0 : size+c.RAEAD.Overhead()]
	_, err = io.ReadFull(c.ReadWriter, raw)
	if err != nil {
		return
	}
	_, err = c.Open(raw[:0], raw)
	if err != nil {
		return
	}
	raw = raw[:size]
	nn := copy(p[n:], raw)
	if len(raw[nn:]) > 0 {
		c.cache = raw[nn:]
	}
	return nn + n, nil
}
func (c *aeadTunnel) Write(p []byte) (n int, err error) {
	if c.WAEAD == nil {
		salt := make([]byte, c.model.SaltSize)
		if _, err = io.ReadFull(rand.Reader, salt); err != nil {
			return 0, err
		}
		if _, err = c.ReadWriter.Write(salt); err != nil {
			return 0, err
		}
		key := make([]byte, c.model.KeySize)
		hkdfSHA1(c.model.key, salt, []byte("ss-subkey"), key)
		if c.WAEAD, err = c.model.NewAEAD(key); err != nil {
			return 0, err
		}
		if c.buffer == nil {
			c.buffer = make([]byte, 2+c.WAEAD.Overhead()+MaxPayload+c.WAEAD.Overhead())
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
	raw := c.buffer[:2+c.WAEAD.Overhead()+size+c.WAEAD.Overhead()]
	c.Seal(raw[:0], []byte{byte(size >> 8), byte(size)})
	c.Seal(raw[:2+c.WAEAD.Overhead()], p)
	_, err = c.ReadWriter.Write(raw)
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

// 创建一个符合shadowsocks协议的AES-256-GCM加密通道
func NewAES256GCM(password string) (Tunnel, error) {
	key := kdf(password, 32)
	return &aead{
		key:       key,
		KeySize:   32,
		SaltSize:  32,
		NonceSize: 12,
		TagSize:   16,
		NewAEAD: func(key []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		},
	}, nil
}
