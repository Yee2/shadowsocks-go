package main

import (
	"gopkg.in/urfave/cli.v2"
	"os"
	"io"
	"github.com/Yee2/shadowsocks-go"
	"fmt"
)

func main() {
	app := cli.App{
		Name:        "fileProtector",
		Description: "用来保护你的文件的",
	}
	app.Version = "201809"
	app.Flags = []cli.Flag{
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
			Action: encrypt,
		},
		{
			Name:   "decrypt",
			Action: decrypt,
		},
	}
	err := app.Run(os.Args)
	if err != nil{
		fmt.Println(err)
	}
}

func encrypt(ctx *cli.Context) (err error) {
	t, err := shadowsocks.NewTunnel(ctx.String("method"), ctx.String("key"))
	if err != nil {
		return err
	}
	r, err := os.Open(ctx.String("in"))
	if err != nil {
		return err
	}
	defer r.Close()
	out := ctx.String("out")
	if out == "" {
		out = ctx.String("in") + ".encrypted"
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

func decrypt(ctx *cli.Context) (err error) {
	t, err := shadowsocks.NewTunnel(ctx.String("method"), ctx.String("key"))
	if err != nil {
		return err
	}
	r, err := os.Open(ctx.String("in"))
	if err != nil {
		return err
	}
	defer r.Close()
	out := ctx.String("out")
	if out == "" {
		out = ctx.String("in") + ".decrypted"
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
