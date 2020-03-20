package main

import (
	"fmt"
	"github.com/Yee2/shadowsocks-go"
	"github.com/urfave/cli/v2"
	"io"
	"os"
)

func main() {
	app := cli.App{
		Name:        "fileProtector",
		Description: "用来保护你的文件的",
	}
	app.Version = "201809"
	flags := []cli.Flag{
		&cli.StringFlag{
			Name:  "in",
			Value: "",
			Usage: "要加密/解密的文件",
		},
		&cli.StringFlag{
			Name:  "key",
			Value: "",
			Usage: "加密密码",
		},
		&cli.StringFlag{
			Name:  "method",
			Value: "aes-256-gcm",
			Usage: "加密方式",
		},
		&cli.StringFlag{
			Name:  "out",
			Value: "",
			Usage: "输出文件",
		},
	}
	app.Commands = []*cli.Command{
		{
			Name:   "encrypt",
			Action: encryptAction,
			Flags:  flags,
		},
		{
			Name:   "decrypt",
			Action: decryptAction,
			Flags:  flags,
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}

func encryptAction(ctx *cli.Context) (err error) {
	return encrypt(
		ctx.String("method"),
		ctx.String("key"),
		ctx.String("in"),
		ctx.String("out"),
	)
}
func encrypt(method, key, in, out string) (err error) {
	t, err := shadowsocks.NewTunnel(method, key)
	if err != nil {
		return err
	}
	r, err := os.Open(in)
	if err != nil {
		return err
	}
	defer r.Close()
	if out == "" {
		out = in + ".encrypted"
	}
	w, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer w.Close()
	we, err := t.Shadow(w)
	if err != nil {
		return err
	}
	_, err = io.Copy(we, r)
	if err != nil {
		return err
	}
	fmt.Println("文件加密保存到 : ", out)
	return nil
}

func decryptAction(ctx *cli.Context) (err error) {
	return decrypt(
		ctx.String("method"),
		ctx.String("key"),
		ctx.String("in"),
		ctx.String("out"),
	)
}

func decrypt(method, key, in, out string) (err error) {
	t, err := shadowsocks.NewTunnel(method, key)
	if err != nil {
		return err
	}
	r, err := os.Open(in)
	if err != nil {
		return err
	}
	defer r.Close()
	if out == "" {
		out = in + ".decrypted"
	}
	w, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer w.Close()
	de, err := t.Shadow(r)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, de)
	if err != nil {
		return err
	}
	fmt.Println("文件解密保存到 : ", out)
	return nil
}
