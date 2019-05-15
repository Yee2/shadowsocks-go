// 这是一个使用Shadowsocks代理HTTP请求的栗子
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/Yee2/shadowsocks-go"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

var dialer = &net.Dialer{}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("%s shadowsocks-uri\n", os.Args[0])
	}
	info, err := Parse(os.Args[1])
	p, _ := info.User.Password()
	t, err := shadowsocks.NewTunnel(info.User.Username(), p)
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, e error) {
			conn, e = dialer.DialContext(ctx, "tcp", info.Host)
			if e != nil {
				return conn, errors.Wrap(err, "unable to connect to shadowsocks server")
			}
			defer func() {
				if e != nil {
					conn.Close()
				}
			}()
			rw, err := t.Shadow(conn)
			if err != nil {
				return nil, errors.Wrap(err, "failed to create encrypted channel")
			}
			res := strings.SplitN(addr, ":", 2)
			if len(res) != 2 {
				return nil, fmt.Errorf("wrong address")
			}
			port, err := strconv.Atoi(res[1])
			if err != nil {
				return nil, errors.Wrap(err, "wrong port number")
			}
			ip := net.ParseIP(res[0])
			if ip := ip.To4(); ip != nil {
				_, err := rw.Write([]byte{0x01, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)})
				if err != nil {
					return conn, errors.Wrap(err, "write data error")
				}
			} else if ip := ip.To16(); ip != nil {
				b := bytes.NewBuffer([]byte{0x04})
				b.Write(ip)
				b.WriteByte(byte(port >> 8))
				b.WriteByte(byte(port >> 0))
				_, err := b.WriteTo(rw)
				if err != nil {
					return conn, errors.Wrap(err, "write data error")
				}
			} else {
				b := bytes.NewBuffer([]byte{0x03})
				b.WriteByte(byte(len(res[0])))
				b.WriteString(res[0])
				b.WriteByte(byte(port >> 8))
				b.WriteByte(byte(port >> 0))
				_, err := b.WriteTo(rw)
				if err != nil {
					return conn, errors.Wrap(err, "write data error")
				}
			}
			return &Conn{conn, rw}, e
		}},
	}
	response, err := client.Get("https://ifconfig.co/")
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Your IP is %s.\n", bytes.TrimSpace(body))
}

type Conn struct {
	net.Conn
	rw io.ReadWriter
}

func (c *Conn) Read(p []byte) (n int, err error) {
	return c.rw.Read(p)

}
func (c *Conn) Write(p []byte) (n int, err error) {
	return c.rw.Write(p)
}

func Parse(s string) (*url.URL, error) {
	info, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if info.Scheme != "ss" {
		return nil, errors.New("not support")
	}
	if info.User == nil && info.Host != "" {
		data, err := base64.StdEncoding.DecodeString(info.Host)
		if err != nil {
			return nil, err
		}
		info, err = url.Parse("ss://" + string(data))
		if err != nil {
			return nil, err
		}
	}
	if _, yes := info.User.Password(); !yes {
		data, err := base64.StdEncoding.DecodeString(info.User.Username())
		if err != nil {
			return nil, err
		}
		res := bytes.SplitN(data, []byte{':'}, 2)
		info.User = url.UserPassword(string(res[0]), string(res[1]))
	}
	return info, nil
}
