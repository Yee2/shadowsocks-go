package shadowsocks

import (
	"errors"
	"fmt"
	"io"
	"shadowsocks/ciphers/core"
)

type Tunnel = core.Tunnel

type Closeable struct {
	io.ReadWriter
}

func (c *Closeable) Close() error {
	return nil
}

var CipherNotSupported = errors.New("cipher not supported")
var AlreadyRegistered = errors.New("already registered")
var providers = make([]core.TunnelProvider, 0)

func Register(p core.TunnelProvider) error {
	for i := range providers {
		if p.Name() == providers[i].Name() {
			return AlreadyRegistered
		}
	}
	providers = append(providers, p)
	return nil
}

// NewTunnel make a new shadowsocks channel
func NewTunnel(method, password string) (Tunnel, error) {
	for _, p := range providers {
		if p.Name() == method {
			return p.New(password), nil
		}
	}
	return nil, fmt.Errorf("%w:%s", CipherNotSupported, method)
}

// Supported Get the supported encryption methods
func Supported() []string {
	list := make([]string, 0)
	for _, p := range providers {
		list = append(list, p.Name())
	}
	return list
}
