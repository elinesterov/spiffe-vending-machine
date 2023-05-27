package workload

import (
	"context"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Config struct {
	TrustDomain spiffeid.TrustDomain
	Log         *zap.Logger
}

// Handler implements the Workload API interface
type Handler struct {
	workload.UnsafeSpiffeWorkloadAPIServer
	c Config
}

func New(c Config) *Handler {
	return &Handler{
		c: c,
	}
}

// FetchJWTSVID processes request for a JWT-SVID. In case of multiple fetched SVIDs with same hint, the SVID that has the oldest
// associated entry will be returned.
func (h *Handler) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (resp *workload.JWTSVIDResponse, err error) {

	if len(req.Audience) == 0 {
		h.c.Log.Error("Missing required audience parameter")
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}

	if req.SpiffeId != "" {
		if _, err := spiffeid.FromString(req.SpiffeId); err != nil {
			h.c.Log.Error("Invalid requested SPIFFE ID", zap.String("spiffe_id", req.GetSpiffeId()), zap.Error(err))
			return nil, status.Errorf(codes.InvalidArgument, "invalid requested SPIFFE ID: %v", err)
		}
	}

	// TODO: implement fake fetch jwt svid

	return &workload.JWTSVIDResponse{}, status.Errorf(codes.Unimplemented, "not implemented")
}

// FetchJWTBundles processes request for JWT bundles
func (h *Handler) FetchJWTBundles(req *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	h.c.Log.Debug("Received JWT bundles request")
	ctx := stream.Context()

	// TODO: figure out streaming shortcut here

	for {
		select {
		case <-time.After(time.Millisecond * 10):
			return status.Errorf(codes.Unimplemented, "not implemented")
		case <-ctx.Done():
			return nil
		}
	}
}

// ValidateJWTSVID processes request for JWT-SVID validation
func (h *Handler) ValidateJWTSVID(ctx context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	h.c.Log.Debug("Received JWT-SVID validation request")

	if req.Audience == "" {
		h.c.Log.Error("Missing required audience parameter")
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}
	if req.Svid == "" {
		h.c.Log.Error("Missing required svid parameter")
		return nil, status.Error(codes.InvalidArgument, "svid must be specified")
	}

	// TODO: get bundles and validate

	return &workload.ValidateJWTSVIDResponse{}, status.Errorf(codes.Unimplemented, "not implemented")
}

// FetchX509SVID processes request for a x509 SVID. In case of multiple fetched SVIDs with same hint, the SVID that has the oldest
// associated entry will be returned.
func (h *Handler) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	h.c.Log.Debug("Received X509 SVID request")
	ctx := stream.Context()

	// TODO: implement fake SVID fetching
	for {
		select {
		case <-time.After(time.Millisecond * 10):
			return status.Errorf(codes.Unimplemented, "not implemented")
		case <-ctx.Done():
			return nil
		}
	}
}

// FetchX509Bundles processes request for x509 bundles
func (h *Handler) FetchX509Bundles(_ *workload.X509BundlesRequest, stream workload.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	h.c.Log.Debug("Received X509 bundles request")
	ctx := stream.Context()

	// TODO imlement fake bundle fetching
	for {
		select {
		case <-time.After(time.Millisecond * 10):
			return status.Errorf(codes.Unimplemented, "not implemented")
		case <-ctx.Done():
			return nil
		}
	}
}
