# <(￣︶￣)↗[GO!] A shadowsocks implementation in pure go

[![GoDoc](https://godoc.org/github.com/Yee2/shadowsocks-go?status.svg)](https://pkg.go.dev/github.com/Yee2/shadowsocks-go)

## Install

```shell
go get github.com/Yee2/shadowsocks-go
```

## Usage

shadowsocks-go provides a Go version implementation of the shadowsocks protocol, supporting AEAD encryption and Stream
encryption. The main working principle is to encode a pipe for plaintext transmission, and data written to the pipe will
be automatically encrypted, while data read from the pipe will be automatically decrypted.

```go
package main

import (
	"bytes"
	"github.com/Yee2/shadowsocks-go"
	"log"
)

func main() {
	buf := new(bytes.Buffer)
	// Create a shadowsocks configuration
	tunnel, err := shadowsocks.NewTunnel("aes-256-gcm", "12345678")
	checkErr(err)

	// shadow the channel
	shaded, err := tunnel.Shadow(&shadowsocks.Closeable{ReadWriter: buf})
	checkErr(err)

	// Close channel will free some reusable resources like bytes buffer etc
	defer shaded.Close()

	// Write data is automatically encrypted and read data is automatically decrypted
	_, err = shaded.Write([]byte("hello shadowsocks!"))
	checkErr(err)
	var data [32]byte
	n, err := shaded.Read(data[:])
	checkErr(err)
	log.Printf("%s\n", data[:n])
}

func checkErr(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

```

## Links

- [shadowsocks](https://shadowsocks.org/)
- [go-shadowsocks2](https://github.com/shadowsocks/go-shadowsocks2)