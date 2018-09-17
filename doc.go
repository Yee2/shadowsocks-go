/*
快速创建一个shadowsocks服务器：
    package main

    import (
    	"net"
    	"log"
    	"github.com/Yee2/shadowsocks-go"
    	"github.com/Yee2/logf"
    )

    func main() {
    	tunnel,err := shadowsocks.NewAES256GCM("123456")
    	if err != nil{
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
    			surface, err :=tunnel.Shadow(conn)
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
*/
package shadowsocks
