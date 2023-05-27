package endpoints

import (
	"net"

	workload_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/elinesterov/spiffe-vending-machine/pkg/agent/endpoints/workload"

	"go.uber.org/zap"
)

type Config struct {
	BindAddr net.Addr

	Log *zap.Logger

	TrustDomain spiffeid.TrustDomain

	// Hooks used by the unit tests to assert that the configuration provided
	// to each handler is correct and return fake handlers.
	newWorkloadAPIServer func(workload.Config) workload_pb.SpiffeWorkloadAPIServer
}
