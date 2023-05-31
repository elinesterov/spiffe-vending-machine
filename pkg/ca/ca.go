package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"go.uber.org/zap"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	// backdate = 10 * time.Second

	// DefaultX509CATTL is the TTL given to X509 CAs if not overridden by
	// the server config.
	DefaultX509CATTL = time.Hour * 24

	// DefaultX509SVIDTTL is the TTL given to X509 SVIDs if not overridden by
	// the server config.
	DefaultX509SVIDTTL = time.Hour

	// DefaultJWTSVIDTTL is the TTL given to JWT SVIDs if a different TTL is
	// not provided in the signing request.
	DefaultJWTSVIDTTL = time.Minute * 5

	// NotBeforeCushion is how much of a cushion to subtract from the current
	// time when determining the notBefore field of certificates to account
	// for clock skew.
	NotBeforeCushion = 10 * time.Second
)

// ServerCA is an interface for Server CAs
type ServerCA interface {
	SignWorkloadX509SVID(ctx context.Context, params WorkloadX509SVIDParams) ([]*x509.Certificate, error)
	SignWorkloadJWTSVID(ctx context.Context, params WorkloadJWTSVIDParams) (string, error)
}

// WorkloadX509SVIDParams are parameters relevant to workload X509-SVID creation
type WorkloadX509SVIDParams struct {
	// Public Key
	PublicKey crypto.PublicKey

	// SPIFFE ID of the SVID
	SPIFFEID spiffeid.ID

	// DNSNames is used to add DNS SAN's to the X509 SVID. The first entry
	// is also added as the CN.
	DNSNames []string

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the certificate will be capped to that of the signing cert.
	TTL time.Duration

	// Subject of the SVID. Default subject is used if it is empty.
	Subject pkix.Name
}

// WorkloadJWTSVIDParams are parameters relevant to workload JWT-SVID creation
type WorkloadJWTSVIDParams struct {
	// SPIFFE ID of the SVID
	SPIFFEID spiffeid.ID

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the token will be capped to that of the signing key.
	TTL time.Duration

	// Audience is used for audience claims
	Audience []string
}

type X509CA struct {
	// Signer is used to sign child certificates.
	Signer crypto.Signer

	// Certificate is the CA certificate.
	Certificate *x509.Certificate

	// UpstreamChain contains the CA certificate and intermediates necessary to
	// chain back to the upstream trust bundle. It is only set if the CA is
	// signed by an UpstreamCA.
	UpstreamChain []*x509.Certificate
}

type JWTKey struct {
	// The signer used to sign keys
	Signer crypto.Signer

	// Kid is the JWT key ID (i.e. "kid" claim)
	Kid string

	// NotAfter is the expiration time of the JWT key.
	NotAfter time.Time
}

type Config struct {
	Log         *zap.Logger
	Clock       clock.Clock
	TrustDomain spiffeid.TrustDomain
	JWTIssuer   string
	JWTSVIDTTL  time.Duration
	X509SVIDTTL time.Duration
}

type CA struct {
	c Config

	mu          sync.RWMutex
	x509CA      *X509CA
	x509CAChain []*x509.Certificate
	jwtKey      *JWTKey
}

func NewCA(config Config) *CA {
	if config.Clock == nil {
		config.Clock = clock.New()
	}

	ca := &CA{
		c: config,
	}

	return ca
}

func (ca *CA) X509CA() *X509CA {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.x509CA
}

func (ca *CA) SetX509CA(x509CA *X509CA) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.x509CA = x509CA
	switch {
	case x509CA == nil:
		ca.x509CAChain = nil
	default:
		ca.x509CAChain = []*x509.Certificate{x509CA.Certificate}
	}
}

func (ca *CA) JWTKey() *JWTKey {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.jwtKey
}

func (ca *CA) SetJWTKey(jwtKey *JWTKey) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.jwtKey = jwtKey
}

func (ca *CA) SignWorkloadX509SVID(ctx context.Context, params WorkloadX509SVIDParams) ([]*x509.Certificate, error) {

	// TODO: we probably don't need this because we won't use chain
	// x509CA, caChain, err := ca.getX509CA()
	// if err != nil {
	// 	return nil, err
	// }
	x509CA := ca.X509CA()
	if ca.x509CA == nil {
		return nil, errors.New("X509 CA is not available for signing")
	}

	// template, err := BuildWorkloadX509SVIDTemplate(ca.c.TrustDomain, ca.x509CA.Certificate, WorkloadX509SVIDParams{
	// 	// ParentChain: caChain,
	// 	PublicKey: params.PublicKey,
	// 	SPIFFEID:  params.SPIFFEID,
	// 	DNSNames:  params.DNSNames,
	// 	TTL:       params.TTL,
	// 	Subject:   params.Subject,
	// })
	// if err != nil {
	// 	return nil, err
	// }

	if params.SPIFFEID.IsZero() {
		return nil, errors.New("invalid X509-SVID ID: cannot be empty")
	}

	if err := verifyTrustDomainMemberID(ca.c.TrustDomain, params.SPIFFEID); err != nil {
		return nil, fmt.Errorf("invalid X509-SVID ID: %w", err)
	}

	serialNumber, err := x509util.NewSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to get new serial number: %w", err)
	}

	subjectKeyID, err := x509util.GetSubjectKeyID(params.PublicKey)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		URIs:                  []*url.URL{params.SPIFFEID.URL()},
		SubjectKeyId:          subjectKeyID,
		BasicConstraintsValid: true,
		PublicKey:             params.PublicKey,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	if params.Subject.String() != "" {
		template.Subject = params.Subject
	} else {
		template.Subject = DefaultX509SVIDSubject()
	}

	// Explicitly set the AKI on the signed certificate, otherwise it won't be
	// added if the subject and issuer match (however unlikely).
	template.AuthorityKeyId = x509CA.Certificate.SubjectKeyId

	// calculate the notBefore and notAfter values for SVID
	// we don't need chain right now but why not
	parentChan := append([]*x509.Certificate{x509CA.Certificate}, x509CA.UpstreamChain...)
	template.NotBefore, template.NotAfter = computeX509SVIDLifetime(ca.c.Clock, parentChan, params.TTL)

	svidChain, err := ca.signX509SVID(x509CA, template)
	if err != nil {
		return nil, err
	}

	return svidChain, nil
}

func (ca *CA) SignWorkloadJWTSVID(ctx context.Context, params WorkloadJWTSVIDParams) (string, error) {
	jwtKey := ca.JWTKey()
	if jwtKey == nil {
		return "", errors.New("JWT key is not available for signing")
	}

	// claims, err := BuildWorkloadJWTSVIDClaims(ctx, WorkloadJWTSVIDParams{
	// 	SPIFFEID: params.SPIFFEID,
	// 	Audience: params.Audience,
	// 	TTL:      params.TTL,
	// 	// ExpirationCap: jwtKey.NotAfter,
	// }, jwtKey.NotAfter)
	// if err != nil {
	// 	return "", err
	// }

	params.Audience = dropEmptyValues(params.Audience)

	if params.SPIFFEID.IsZero() {
		return "", errors.New("invalid JWT-SVID ID: cannot be empty")
	}

	if err := verifyTrustDomainMemberID(ca.c.TrustDomain, params.SPIFFEID); err != nil {
		return "", fmt.Errorf("invalid JWT-SVID ID: %w", err)
	}

	if len(params.Audience) == 0 {
		return "", errors.New("invalid JWT-SVID audience: cannot be empty")
	}

	now := ca.c.Clock.Now()

	ttl := params.TTL
	if ttl <= 0 {
		ttl = ca.c.JWTSVIDTTL
	}
	_, expiresAt := computeCappedLifetime(ca.c.Clock, ttl, jwtKey.NotAfter)

	claims := map[string]interface{}{
		"sub": params.SPIFFEID.String(),
		"exp": jwt.NewNumericDate(expiresAt),
		"aud": params.Audience,
		"iat": jwt.NewNumericDate(now),
	}

	if ca.c.JWTIssuer != "" {
		claims["iss"] = ca.c.JWTIssuer
	}

	token, err := ca.signJWTSVID(jwtKey, claims)
	if err != nil {
		return "", fmt.Errorf("unable to sign JWT SVID: %w", err)
	}

	return token, nil
}

// func (ca *CA) getX509CA() (*X509CA, []*x509.Certificate, error) {
// 	ca.mu.RLock()
// 	defer ca.mu.RUnlock()
// 	if ca.x509CA == nil {
// 		return nil, nil, errors.New("X509 CA is not available for signing")
// 	}
// 	return ca.x509CA, ca.x509CAChain, nil
// }

func (ca *CA) signX509SVID(x509CA *X509CA, template *x509.Certificate) ([]*x509.Certificate, error) {
	x509SVID, err := x509util.CreateCertificate(template, x509CA.Certificate, template.PublicKey, x509CA.Signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign X509 SVID: %w", err)
	}

	return []*x509.Certificate{x509SVID}, nil
}

func (ca *CA) signJWTSVID(jwtKey *JWTKey, claims map[string]interface{}) (string, error) {
	alg, err := cryptoutil.JoseAlgFromPublicKey(jwtKey.Signer.Public())
	if err != nil {
		return "", fmt.Errorf("failed to determine JWT key algorithm: %w", err)
	}

	jwtSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(jwtKey.Signer),
				KeyID: jwtKey.Kid,
			},
		},
		new(jose.SignerOptions).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to configure JWT signer: %w", err)
	}

	signedToken, err := jwt.Signed(jwtSigner).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT SVID: %w", err)
	}

	return signedToken, nil
}
