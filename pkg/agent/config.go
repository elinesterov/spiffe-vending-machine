package agent

import (
	"net"

	"go.uber.org/zap"
)

type Config struct {
	BindAddress net.Addr
	Log         *zap.Logger
}

func New(c *Config) *Agent {
	return &Agent{
		c: c,
	}
}
