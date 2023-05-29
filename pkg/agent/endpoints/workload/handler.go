package workload

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var ErrNotImplemented = status.Errorf(codes.Unimplemented, "Under Construction")

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

	return nil, ErrNotImplemented
}

// FetchJWTBundles processes request for JWT bundles
func (h *Handler) FetchJWTBundles(req *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	h.c.Log.Debug("Received JWT bundles request")

	// TODO: figure out streaming shortcut here

	return ErrNotImplemented
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

	return nil, ErrNotImplemented
}

// FetchX509SVID processes request for a x509 SVID. In case of multiple fetched SVIDs with same hint, the SVID that has the oldest
// associated entry will be returned.
func (h *Handler) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	h.c.Log.Debug("Received X509 SVID request")

	// TODO: implement fake SVID fetching
	return ErrNotImplemented
}

// FetchX509Bundles processes request for x509 bundles
func (h *Handler) FetchX509Bundles(_ *workload.X509BundlesRequest, stream workload.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	h.c.Log.Debug("Received X509 bundles request")

	// TODO imlement fake bundle fetching
	return ErrNotImplemented
}
