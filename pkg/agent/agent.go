package agent

import (
	"context"
	"errors"
	_ "net/http/pprof" //nolint: gosec // import registers routes on DefaultServeMux

	"github.com/elinesterov/spiffe-vending-machine/pkg/agent/endpoints"
	"github.com/elinesterov/spiffe-vending-machine/pkg/common/util"
	_ "golang.org/x/net/trace" // registers handlers on the DefaultServeMux
)

type Agent struct {
	c *Config
}

// Run the agent
// This method initializes the agent, including its plugins,
// and then blocks on the main event loop.
func (a *Agent) Run(ctx context.Context) error {

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	endpoints := a.newEndpoints()

	tasks := []func(context.Context) error{
		endpoints.ListenAndServe,
	}

	err := util.RunTasks(ctx, tasks...)
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

func (a *Agent) newEndpoints() endpoints.Server {
	return endpoints.New(endpoints.Config{
		BindAddr: a.c.BindAddress,
		Log:      a.c.Log.Named("endpoints"),
	})
}
