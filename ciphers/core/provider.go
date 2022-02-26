package core

type TunnelProvider interface {
	Name() string
	New(password string) Tunnel
}
