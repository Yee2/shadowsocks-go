package main

import (
	"bytes"
	"log"
	"shadowsocks"
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
