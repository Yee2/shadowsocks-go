# <(￣︶￣)↗[GO!] A shadowsocks implementation in pure go
[![GoDoc](https://godoc.org/github.com/Yee2/shadowsocks-go?status.svg)](https://godoc.org/github.com/Yee2/shadowsocks-go)

## 支持的方法:
* aes-128-cfb
* aes-192-cfb
* aes-256-cfb
* aes-128-ctr
* aes-192-ctr
* aes-256-ctr
* camellia-128-cfb
* camellia-192-cfb
* camellia-256-cfb
* aes-128-gcm
* aes-192-gcm
* aes-256-gcm

## 加密文件例子

```go
package main

import (
	"github.com/Yee2/shadowsocks-go"
	"os"
	"io"
	"fmt"
	"log"
)

func main() {
	t, err := shadowsocks.NewTunnel("aes-256-gcm", "123456")
	if err != nil {
		log.Fatalln(err)
	}
	r, err := os.Open("origin.txt")
	if err != nil {
		log.Fatalln(err)
	}
	defer r.Close()
	out := "origin.txt.encrypted"
	w, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalln(err)
	}
	defer w.Close()
	we, err := t.Shadow(w)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = io.Copy(we, r)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("文件加密保存到 : ", out)
}

```
## 构建一个简单的ss服务器
```go
package main

import (
	"github.com/Yee2/logf"
	"github.com/Yee2/shadowsocks-go"
	"log"
	"net"
)

func main() {
	tunnel, err := shadowsocks.NewTunnel("aes-256-gcm","123456")
	if err != nil {
		log.Fatalln(err)
	}
	listener, err := net.Listen("tcp", "0.0.0.0:8366")
	if err != nil {
		log.Fatalln(err)
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			println(err)
			continue
		}
		go func() {
			defer conn.Close()
			surface, err := tunnel.Shadow(conn)
			if err != nil {
				println(err)
				return
			}
			err = shadowsocks.Handle(surface)
			if err != nil {
				logf.Logf("%s", err)
			}
		}()

	}
}

```
## 致谢

* 协议部分参考:[shadowsocks](https://shadowsocks.org/)
* 源码参考:[go-shadowsocks2](https://github.com/shadowsocks/go-shadowsocks2)