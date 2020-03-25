package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/Yee2/shadowsocks-go"
	"github.com/alexflint/go-arg"
	"github.com/pkg/errors"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var timeout = time.Minute * 10

var args struct {
	Server     string `arg:"-s" default:"[::]"`
	Port       int    `arg:"-p" default:"8388"`
	Method     string `arg:"-m" default:"aes-256-gcm"`
	Key        string `arg:"-k"`
	Plugin     string
	PluginOpts string `arg:"--plugin-opts"`
	Verbose    bool   `arg:"-v" help:"Verbose mode"`
}
var bytesBufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 1024))
	},
}

func main() {
	arg.MustParse(&args)
	tunnel, err := shadowsocks.NewTunnel(args.Method, args.Key)
	if err != nil {
		log.Fatalln(err)
	}
	go func() {
		if err := udpServer(context.TODO(), tunnel); err != nil {
			log.Println(err)
		}
	}()
	var (
		listener net.Listener
	)
	ctx, cancel := context.WithCancel(context.Background())
	if args.Plugin != "" {
		listener, err = net.Listen("tcp", "localhost:0")
		if err != nil {
			log.Fatalln("绑定端口失败:", err)
		}
		cmd := exec.Command(args.Plugin)
		if args.Verbose {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, fmt.Sprintf("SS_REMOTE_HOST=%s", args.Server))
		cmd.Env = append(cmd.Env, fmt.Sprintf("SS_REMOTE_PORT=%d", args.Port))
		cmd.Env = append(cmd.Env, "SS_LOCAL_HOST=127.0.0.1")
		cmd.Env = append(cmd.Env, fmt.Sprintf("SS_LOCAL_PORT=%d", listener.Addr().(*net.TCPAddr).Port))
		if args.PluginOpts != "" {
			cmd.Env = append(cmd.Env, fmt.Sprintf("SS_PLUGIN_OPTIONS=%s", args.PluginOpts))
		}
		if err := cmd.Start(); err != nil {
			log.Fatalln("运行插件失败:", err)
		}
		go func() {
			cmd.Wait()
			cancel()
		}()
		go func() {
			<-ctx.Done()
			cmd.Process.Kill()
		}()
	} else {
		listener, err = net.Listen("tcp", fmt.Sprintf("%s:%d", args.Server, args.Port))
		if err != nil {
			log.Fatalln("绑定端口失败:", err)
		}
	}
	defer listener.Close()
	go func() {

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
					log.Println(err)
				}
			}()

		}

	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-signals:
	case <-ctx.Done():
	}
	log.Println("正在关闭 ss-server.")
	cancel()
}

func udpServer(ctx context.Context, tunnel shadowsocks.Tunnel) error {
	var buffer [1024]byte
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", args.Server, args.Port))
	if err != nil {
		return fmt.Errorf("parsing address error:%w", err)
	}
	pc, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("an error occurred on the listening port:%w", err)
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
			fmt.Println(errors.Wrap(err, "parsing address error"))
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
		subCtx, cancel := context.WithCancel(ctx)
		listener, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if err != nil {
			fmt.Println(err)
			continue
		}
		// 注册到会话表里面
		mu.Lock()
		table[server.String()] = listener
		mu.Unlock()
		// 会话过期或者出现错误，删除
		go func(ctx context.Context) {
			<-ctx.Done()
			mu.Lock()
			delete(table, server.String())
			mu.Unlock()
		}(subCtx)
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
						log.Printf("error:%s\n", err)
						cancel()
					}
					wb := bytesBufferPool.Get().(*bytes.Buffer)
					if server.IP.To4() != nil {
						wb.WriteByte(0x01)
						wb.Write(server.IP.To4())
						// 高位在前 低位在后
						wb.WriteByte(byte(server.Port >> 8))
						wb.WriteByte(byte(server.Port))
						wb.Write(buffer[:n])
					} else if server.IP.To16() != nil {
						wb.WriteByte(0x04)
						wb.Write(server.IP.To16())
						// 高位在前 低位在后
						wb.WriteByte(byte(server.Port >> 8))
						wb.WriteByte(byte(server.Port))
						wb.Write(buffer[:n])
					} else {
						cancel()
						wb.Reset()
						bytesBufferPool.Put(wb)
						return
					}
					n, _ = tunnel.Pack(buffer[:], wb.Bytes())
					pc.WriteToUDP(buffer[:n], client)
					wb.Reset()
					bytesBufferPool.Put(wb)
					timer, _ = context.WithTimeout(ctx, timeout)
				}
			}
		}(subCtx)

	}
	return nil
}
