package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// DefaultX509CASubject is the default subject set on workload X509SVIDs
// TODO: This is a historic, but poor, default. We should revisit (see issue #3841).
func DefaultX509CASubject() pkix.Name {
	return pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"SPIFFE"},
	}
}

// DefaultX509SVIDSubject is the default subject set on workload X509SVIDs
// TODO: This is a historic, but poor, default. We should revisit (see issue #3841).
func DefaultX509SVIDSubject() pkix.Name {
	return pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"SPIRE"},
	}
}

// // We need this function
// func BuildWorkloadX509SVIDTemplate(trustDomain spiffeid.TrustDomain, parentCert *x509.Certificate, params WorkloadX509SVIDParams) (*x509.Certificate, error) {

// 	tmpl, err := buildX509SVIDTemplate(trustDomain, params.SPIFFEID, params.PublicKey, params.Subject, params.TTL)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// TODO: I'm not sure we want this
// 	// The first DNS name is also added as the CN by default. This happens
// 	// even if the subject is provided explicitly in the params for backwards
// 	// compatibility. Ideally we wouldn't do override the subject in this
// 	// case. It is still overridable via the credential composers however.
// 	// if len(params.DNSNames) > 0 {
// 	// 	tmpl.Subject.CommonName = params.DNSNames[0]
// 	// 	tmpl.DNSNames = params.DNSNames
// 	// }

// 	// TODO: not sure we are care about composer either
// 	// for _, cc := range b.config.CredentialComposers {
// 	// 	attributes, err := cc.ComposeWorkloadX509SVID(ctx, params.SPIFFEID, params.PublicKey, x509SVIDAttributesFromTemplate(tmpl))
// 	// 	if err != nil {
// 	// 		return nil, err
// 	// 	}
// 	// 	applyX509SVIDAttributes(tmpl, attributes)
// 	// }

// 	return tmpl, nil
// }

// We need this function
// func BuildWorkloadJWTSVIDClaims(ctx context.Context, params WorkloadJWTSVIDParams, expirationCap time.Time) (map[string]interface{}, error) {
// 	params.Audience = dropEmptyValues(params.Audience)

// 	if params.SPIFFEID.IsZero() {
// 		return nil, errors.New("invalid JWT-SVID ID: cannot be empty")
// 	}

// 	if err := verifyTrustDomainMemberID(b.config.TrustDomain, params.SPIFFEID); err != nil {
// 		return nil, fmt.Errorf("invalid JWT-SVID ID: %w", err)
// 	}

// 	if len(params.Audience) == 0 {
// 		return nil, errors.New("invalid JWT-SVID audience: cannot be empty")
// 	}

// 	now := b.config.Clock.Now()

// 	ttl := params.TTL
// 	if ttl <= 0 {
// 		ttl = b.config.JWTSVIDTTL
// 	}
// 	_, expiresAt := computeCappedLifetime(b.config.Clock, ttl, expirationCap)

// 	attributes := credentialcomposer.JWTSVIDAttributes{
// 		Claims: map[string]interface{}{
// 			"sub": params.SPIFFEID.String(),
// 			"exp": jwt.NewNumericDate(expiresAt),
// 			"aud": params.Audience,
// 			"iat": jwt.NewNumericDate(now),
// 		},
// 	}
// 	if b.config.JWTIssuer != "" {
// 		attributes.Claims["iss"] = b.config.JWTIssuer
// 	}

// 	for _, cc := range b.config.CredentialComposers {
// 		var err error
// 		attributes, err = cc.ComposeWorkloadJWTSVID(ctx, params.SPIFFEID, attributes)
// 		if err != nil {
// 			return nil, err
// 		}
// 	}

// 	return attributes.Claims, nil
// }

// we need this function
// func buildX509SVIDTemplate(trustDomain spiffeid.TrustDomain, spiffeID spiffeid.ID, publicKey crypto.PublicKey, subject pkix.Name, ttl time.Duration) (*x509.Certificate, error) {
// 	if spiffeID.IsZero() {
// 		return nil, errors.New("invalid X509-SVID ID: cannot be empty")
// 	}

// 	if err := verifyTrustDomainMemberID(trustDomain, spiffeID); err != nil {
// 		return nil, fmt.Errorf("invalid X509-SVID ID: %w", err)
// 	}

// 	serialNumber, err := x509util.NewSerialNumber()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get new serial number: %w", err)
// 	}

// 	subjectKeyID, err := x509util.GetSubjectKeyID(publicKey)
// 	if err != nil {
// 		return nil, err
// 	}

// 	tmpl := &x509.Certificate{
// 		SerialNumber:          serialNumber,
// 		URIs:                  []*url.URL{spiffeID.URL()},
// 		SubjectKeyId:          subjectKeyID,
// 		BasicConstraintsValid: true,
// 		PublicKey:             publicKey,
// 	}

// 	if subject.String() != "" {
// 		tmpl.Subject = subject
// 	} else {
// 		tmpl.Subject = DefaultX509SVIDSubject()
// 	}

// 	tmpl.KeyUsage = x509.KeyUsageKeyEncipherment |
// 		x509.KeyUsageKeyAgreement |
// 		x509.KeyUsageDigitalSignature
// 	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{
// 		x509.ExtKeyUsageServerAuth,
// 		x509.ExtKeyUsageClientAuth,
// 	}

// 	// not sure we want this
// 	// Append the unique ID to the subject, unless disabled
// 	// tmpl.Subject.ExtraNames = append(tmpl.Subject.ExtraNames, x509svid.UniqueIDAttribute(spiffeID))

// 	return tmpl, nil
// }

// func applyX509SVIDAttributes(tmpl *x509.Certificate, attribs credentialcomposer.X509SVIDAttributes) {
// 	tmpl.Subject = attribs.Subject
// 	tmpl.DNSNames = attribs.DNSNames
// 	tmpl.ExtraExtensions = attribs.ExtraExtensions
// }

func computeX509SVIDLifetime(clock clock.Clock, parentChain []*x509.Certificate, ttl time.Duration) (notBefore, notAfter time.Time) {
	if ttl <= 0 {
		ttl = DefaultX509SVIDTTL
	}
	return computeCappedLifetime(clock, ttl, parentChainExpiration(parentChain))
}

func computeCappedLifetime(clk clock.Clock, ttl time.Duration, expirationCap time.Time) (notBefore, notAfter time.Time) {
	now := clk.Now()
	notBefore = now.Add(-NotBeforeCushion)
	notAfter = now.Add(ttl)
	if !expirationCap.IsZero() && notAfter.After(expirationCap) {
		notAfter = expirationCap
	}
	return notBefore, notAfter
}

func parentChainExpiration(parentChain []*x509.Certificate) time.Time {
	var expiration time.Time
	if len(parentChain) > 0 && !parentChain[0].NotAfter.IsZero() {
		expiration = parentChain[0].NotAfter
	}
	return expiration
}

func dropEmptyValues(ss []string) []string {
	next := 0
	for _, s := range ss {
		if s != "" {
			ss[next] = s
			next++
		}
	}
	ss = ss[:next]
	return ss
}

func verifyTrustDomainMemberID(trustDomain spiffeid.TrustDomain, id spiffeid.ID) error {

	// Verify the SPIFFE ID is a member of the trust domain
	if !id.MemberOf(trustDomain) {
		return fmt.Errorf("invalid X509-SVID ID: %q is not a member of %q", id, trustDomain)
	}

	// Verify the SPIFFE ID path is not empty
	if id.Path() == "" {
		return fmt.Errorf("invalid X509-SVID ID: missing SPIFFE ID path")
	}

	return nil
}
