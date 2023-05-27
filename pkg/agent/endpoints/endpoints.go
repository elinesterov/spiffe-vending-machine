package endpoints

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	workload_pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/elinesterov/spiffe-vending-machine/pkg/agent/endpoints/workload"
)

type Server interface {
	ListenAndServe(ctx context.Context) error
}

type Endpoints struct {
	addr              net.Addr
	log               *zap.Logger
	workloadAPIServer workload_pb.SpiffeWorkloadAPIServer
}

func New(c Config) *Endpoints {

	if c.newWorkloadAPIServer == nil {
		c.newWorkloadAPIServer = func(c workload.Config) workload_pb.SpiffeWorkloadAPIServer {
			return workload.New(c)
		}
	}

	workloadAPIServer := c.newWorkloadAPIServer(workload.Config{
		TrustDomain: c.TrustDomain,
	})

	return &Endpoints{
		addr:              c.BindAddr,
		log:               c.Log,
		workloadAPIServer: workloadAPIServer,
	}
}

func (e *Endpoints) ListenAndServe(ctx context.Context) error {

	server := grpc.NewServer()

	workload_pb.RegisterSpiffeWorkloadAPIServer(server, e.workloadAPIServer)

	l, err := e.createListener()
	if err != nil {
		return err
	}
	defer l.Close()

	// Update the listening address with the actual address.
	// If a TCP address was specified with port 0, this will
	// update the address with the actual port that is used
	// to listen.
	e.addr = l.Addr()

	e.log.Info("Starting Workload and SDS APIs",
		zap.String("network", e.addr.Network()),
		zap.String("address", e.addr.String()),
	)

	errChan := make(chan error)
	go func() { errChan <- server.Serve(l) }()

	select {
	case err = <-errChan:
	case <-ctx.Done():
		e.log.Info("Stopping SPIFFE Workload and APIs")
		server.Stop()
		err = <-errChan
		if errors.Is(err, grpc.ErrServerStopped) {
			err = nil
		}
	}
	return err
}

func (e *Endpoints) createUDSListener() (net.Listener, error) {
	// Remove uds if already exists
	os.Remove(e.addr.String())

	unixAddr, ok := e.addr.(*net.UnixAddr)
	if !ok {
		return nil, fmt.Errorf("create UDS listener: address is type %T, not net.UnixAddr", e.addr)
	}

	l, err := net.ListenUnix(e.addr.Network(), unixAddr)
	// l, err := unixListener.ListenUnix(e.addr.Network(), unixAddr)
	if err != nil {
		return nil, fmt.Errorf("create UDS listener: %w", err)
	}

	if err := os.Chmod(e.addr.String(), os.ModePerm); err != nil {
		return nil, fmt.Errorf("unable to change UDS permissions: %w", err)
	}
	return l, nil
}

func (e *Endpoints) createListener() (net.Listener, error) {
	switch e.addr.Network() {
	case "unix":
		return e.createUDSListener()
	case "pipe":
		return nil, errors.New("unsupported platform")
	default:
		return nil, net.UnknownNetworkError(e.addr.Network())
	}
}
