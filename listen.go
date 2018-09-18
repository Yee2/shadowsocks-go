package shadowsocks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
)

// shadowsocks协议实现，在代理服务器和目标之间构建起通道
func Handle(rw io.ReadWriter) (e error) {
	target, err := ParseTarget(rw)
	if err != nil {
		return err
	}
	remote, err := net.Dial("tcp", target)
	if err != nil {
		return err
	}
	defer remote.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		io.Copy(rw, remote)
		cancel()
	}()
	go func() {
		io.Copy(remote, rw)
		cancel()
	}()
	<-ctx.Done()
	return nil
}

// shadowsocks协议实现，从r里面读取目标地址
func ParseTarget(r io.Reader) (address string, e error) {
	var buffer [0xff + 2]byte
	_, e = r.Read(buffer[0:1])
	if e != nil {
		return
	}
	switch buffer[0] {
	case 0x01:
		_, e = io.ReadFull(r, buffer[0:6])
		if e != nil {
			return
		}
		return fmt.Sprintf("%s:%d", net.IP(buffer[0:4]), uint16(buffer[4])<<8|uint16(buffer[5])), nil
	case 0x03:
		_, e = io.ReadFull(r, buffer[0:1])
		if e != nil {
			return
		}
		length := buffer[0]
		_, e = io.ReadFull(r, buffer[0:length+2])
		if e != nil {
			return
		}
		return fmt.Sprintf("%s:%d", buffer[0:length], uint16(buffer[length])<<8|uint16(buffer[length+1])), nil
	case 0x04:
		_, e = io.ReadFull(r, buffer[0:18])
		if e != nil {
			return
		}
		return fmt.Sprintf("%s:%d", net.IP(buffer[0:16]), uint16(buffer[16])<<8|uint16(buffer[17])), nil
	default:
		return "", errors.New("error")
	}
}
