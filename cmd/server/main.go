package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/Yee2/logf"
	"github.com/Yee2/shadowsocks-go"
	"github.com/pkg/errors"
	"log"
	"net"
	"sync"
	"time"
)

var timeout = time.Minute * 10

func main() {
	tunnel, err := shadowsocks.NewTunnel("aes-256-gcm", "123456")
	if err != nil {
		log.Fatalln(err)
	}
	go func() {
		err := UDPserver(tunnel)
		if err != nil {
			logf.Logf("%s", err)
		}
	}()
	listener, err := net.Listen("tcp", "0.0.0.0:8366")
	if err != nil {
		log.Fatalln("绑定端口失败:", err)
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

func UDPserver(tunnel shadowsocks.Tunnel) (error) {
	var buffer [1024]byte
	addr, err := net.ResolveUDPAddr("udp", ":8366")
	if err != nil {
		return err
	}
	pc, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	table := make(map[string]*net.UDPConn, 0)
	mu := &sync.Mutex{}
	for {
		// 总共需要三个地址 分别是 client agent server,
		// 对应客户端地址，代理服务器地址，目标地址，这里的地址包含IP和端口
		n, client, err := pc.ReadFromUDP(buffer[:])
		if err != nil {
			fmt.Println(err)
			continue
		}
		n, err = tunnel.Unpack(buffer[:0], buffer[:n])
		target, err := shadowsocks.ParseTarget(bytes.NewBuffer(buffer[:n]))
		if err != nil {
			fmt.Println(errors.Wrap(err, "Parsing address error"))
			continue
		}

		server, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if listener, ok := table[server.String()]; ok {
			listener.WriteToUDP(shadowsocks.Payload(buffer[:n]), server)
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		listener, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if err != nil {
			fmt.Println(err)
			continue
		}
		mu.Lock()
		table[server.String()] = listener
		mu.Unlock()
		go func(ctx context.Context) {
			<-ctx.Done()
			mu.Lock()
			delete(table, server.String())
			mu.Unlock()
		}(ctx)
		listener.WriteToUDP(shadowsocks.Payload(buffer[:n]), server)
		go func(ctx context.Context) {
			timer, _ := context.WithTimeout(ctx, timeout)
			var buffer [1024]byte
			for {
				select {
				case <-timer.Done():
					cancel()
					return
				default:
					n, _, err := listener.ReadFromUDP(buffer[:])
					if err != nil {
						logf.Logf("error:%s\n", err)
						cancel()
					}
					wb := bytes.NewBuffer([]byte{})
					if server.IP.To4() != nil {
						wb.WriteByte(0x01)
						wb.Write(server.IP.To4())
						// 高位在前 低位在后
						wb.WriteByte(byte(server.Port >> 8))
						wb.WriteByte(byte(server.Port))
						wb.Write(buffer[:n])
					}else if server.IP.To16() != nil{
						wb.WriteByte(0x04)
						wb.Write(server.IP.To16())
						// 高位在前 低位在后
						wb.WriteByte(byte(server.Port >> 8))
						wb.WriteByte(byte(server.Port))
						wb.Write(buffer[:n])
					}else{
						cancel()
						return
					}
					n, _ = tunnel.Pack(buffer[:], wb.Bytes())
					pc.WriteToUDP(buffer[:n], client)
					timer, _ = context.WithTimeout(ctx, timeout)
				}
			}
		}(ctx)

	}
	return nil
}
