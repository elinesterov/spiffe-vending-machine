package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap/zaptest"
)

var (
	testSigner, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt/OIyb8Ossz/5bNk
XtnzFe1T2d0D9quX9Loi1O55b8yhRANCAATDe/2d6z+P095I3dIkocKr4b3zAy+1
qQDuoXqa8i3YOPk5fLib4ORzqD9NJFcrKjI+LLtipQe9yu/eY1K0yhBa
-----END PRIVATE KEY-----
`))

	ctx = context.Background()

	trustDomainExample = spiffeid.RequireTrustDomainFromString("example.org")
	trustDomainFoo     = spiffeid.RequireTrustDomainFromString("foo.com")
)

func TestCA(t *testing.T) {
	suite.Run(t, new(CATestSuite))
}

type CATestSuite struct {
	suite.Suite

	clock        *clock.Mock
	upstreamCert *x509.Certificate
	caCert       *x509.Certificate

	ca *CA
}

func (s *CATestSuite) SetupSuite() {
	s.clock = clock.NewMock(s.T())
	s.clock.Set(time.Now().Truncate(time.Second).UTC())

	s.upstreamCert = s.createCACertificate("UPSTREAMCA", nil)
	s.caCert = s.createCACertificate("CA", s.upstreamCert)
}

func (s *CATestSuite) SetupTest() {
	log := zaptest.NewLogger(s.T())

	s.ca = NewCA(Config{
		Log:         log,
		Clock:       s.clock,
		TrustDomain: trustDomainExample,
		X509SVIDTTL: time.Minute,
	})
	s.setX509CA(true)
	s.setJWTKey()
}

func (s *CATestSuite) TestSignWorkloadX509SVIDNoCASet() {
	s.ca.SetX509CA(nil)
	_, err := s.ca.SignWorkloadX509SVID(ctx, s.createWorkloadX509SVIDParams())
	s.Require().EqualError(err, "X509 CA is not available for signing")
}

func (s *CATestSuite) TestSignWorkloadX509SVID() {
	svidChain, err := s.ca.SignWorkloadX509SVID(ctx, s.createWorkloadX509SVIDParams())
	s.Require().NoError(err)
	s.Require().Len(svidChain, 1)

	svid := svidChain[0]

	s.False(svid.NotBefore.IsZero(), "NotBefore is not set")
	s.False(svid.NotAfter.IsZero(), "NotAfter is not set")
	s.NotEmpty(svid.SubjectKeyId, "SubjectKeyId is not set")
	s.NotEmpty(svid.AuthorityKeyId, "AuthorityKeyId is not set")
	s.Equal(x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement|x509.KeyUsageDigitalSignature, svid.KeyUsage, "key usage does not match")
	s.Equal([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, svid.ExtKeyUsage, "ext key usage does not match")
	s.False(svid.IsCA, "CA bit is set")
	s.True(svid.BasicConstraintsValid, "Basic constraints are not valid")

	// SPIFFE ID should be set to that of the trust domain
	if s.Len(svid.URIs, 1, "has no URIs") {
		s.Equal("spiffe://example.org/workload", svid.URIs[0].String())
	}

	// Subject is calculated by SPIRE Server and should not be pulled from the CSR.
	s.Equal("O=SPIFFE Vending Machine,C=US,2.5.4.45=#13203933323965323863393434383738376466306663623363363535363035653531", svid.Subject.String())
}

func (s *CATestSuite) TestSignWorkloadX509SVIDCannotSignTrustDomainID() {
	params := WorkloadX509SVIDParams{
		SPIFFEID:  spiffeid.RequireFromString("spiffe://example.org"),
		PublicKey: testSigner.Public(),
	}
	_, err := s.ca.SignWorkloadX509SVID(ctx, params)
	s.Require().EqualError(err, `invalid X509-SVID ID: "spiffe://example.org" is not a member of trust domain "example.org"; path is empty`)
}

func (s *CATestSuite) TestSignWorkloadX509SVIDUsesDefaultTTLIfTTLUnspecified() {
	svid, err := s.ca.SignWorkloadX509SVID(ctx, s.createWorkloadX509SVIDParams())
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute), svid[0].NotAfter)
}

func (s *CATestSuite) TestSignWorkloadX509SVIDUsesDefaultTTLAndNoCNDNS() {
	svid, err := s.ca.SignWorkloadX509SVID(ctx, s.createWorkloadX509SVIDParams())
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute), svid[0].NotAfter)
	s.Require().Empty(svid[0].DNSNames)
	s.Require().Empty(svid[0].Subject.CommonName)
}

func (s *CATestSuite) TestSignWorkloadX509SVIDSingleDNS() {
	params := s.createWorkloadX509SVIDParams()
	params.DNSNames = []string{"somehost1"}
	svid, err := s.ca.SignWorkloadX509SVID(ctx, params)
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute), svid[0].NotAfter)
	s.Require().Equal(params.DNSNames, svid[0].DNSNames)
	s.Require().Equal("somehost1", svid[0].Subject.CommonName)
}

func (s *CATestSuite) TestSignWorkloadX509SVIDMultipleDNS() {
	params := s.createWorkloadX509SVIDParams()
	params.DNSNames = []string{"somehost1", "somehost2", "somehost3"}
	svid, err := s.ca.SignWorkloadX509SVID(ctx, params)
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute), svid[0].NotAfter)
	s.Require().Equal(params.DNSNames, svid[0].DNSNames)
	s.Require().Equal("somehost1", svid[0].Subject.CommonName)
}

func (s *CATestSuite) TestSignWorkloadX509SVIDWithSubject() {
	subject := pkix.Name{
		Organization: []string{"ORG"},
		Country:      []string{"US", "EN"},
		CommonName:   "Common Name",
	}
	dns := []string{"dns1", "dns2"}

	testCases := []struct {
		name     string
		dns      []string
		expected string
		subject  pkix.Name
	}{
		{
			name:     "empty subject",
			expected: "O=SPIFFE Vending Machine,C=US,2.5.4.45=#13203933323965323863393434383738376466306663623363363535363035653531",
			subject:  pkix.Name{},
		}, {
			name:     "no subject but DNS",
			dns:      dns,
			expected: "CN=dns1,O=SPIFFE Vending Machine,C=US,2.5.4.45=#13203933323965323863393434383738376466306663623363363535363035653531",
		}, {
			name:     "subject provided",
			expected: "CN=Common Name,O=ORG,C=EN+C=US,2.5.4.45=#13203933323965323863393434383738376466306663623363363535363035653531",
			subject:  subject,
		}, {
			name:     "subject and dns",
			dns:      dns,
			expected: "CN=dns1,O=ORG,C=EN+C=US,2.5.4.45=#13203933323965323863393434383738376466306663623363363535363035653531",
			subject:  subject,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		s.T().Run(testCase.name, func(t *testing.T) {
			params := s.createWorkloadX509SVIDParams()
			params.Subject = testCase.subject
			params.DNSNames = testCase.dns

			svid, err := s.ca.SignWorkloadX509SVID(ctx, params)
			require.NoError(t, err)

			require.Len(t, svid, 1)
			cert := svid[0]
			require.NotNil(t, cert)
			require.Equal(t, testCase.expected, cert.Subject.String())
		})
	}
}

// TODO: maybe later
// func (s *CATestSuite) TestSignWorkloadX509SVIDReturnsChainIfIntermediate() {
// 	s.setX509CA(false)

// 	svid, err := s.ca.SignWorkloadX509SVID(ctx, s.createWorkloadX509SVIDParams())
// 	s.Require().NoError(err)
// 	s.Require().Len(svid, 3)
// 	s.Require().NotNil(svid[0])
// 	s.Require().Equal(s.caCert, svid[1])
// 	s.Require().Equal(s.upstreamCert, svid[2])
// }

func (s *CATestSuite) TestSignWorkloadX509SVIDUsesTTLIfSpecified() {
	params := s.createWorkloadX509SVIDParams()
	params.TTL = time.Minute + time.Second
	svid, err := s.ca.SignWorkloadX509SVID(ctx, params)
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(time.Minute+time.Second), svid[0].NotAfter)
}

func (s *CATestSuite) TestSignWorkloadX509SVIDCapsTTLToCATTL() {
	params := s.createWorkloadX509SVIDParams()
	params.TTL = time.Hour
	svid, err := s.ca.SignWorkloadX509SVID(ctx, params)
	s.Require().NoError(err)
	s.Require().Len(svid, 1)
	s.Require().Equal(s.clock.Now().Add(-backdate), svid[0].NotBefore)
	s.Require().Equal(s.clock.Now().Add(10*time.Minute), svid[0].NotAfter)
}

func (s *CATestSuite) TestSignWorkloadX509SVIDValidatesTrustDomain() {
	_, err := s.ca.SignWorkloadX509SVID(ctx, s.createWorkloadX509SVIDParamsInDomain(trustDomainFoo))
	s.Require().EqualError(err, `invalid X509-SVID ID: "spiffe://foo.com/workload" is not a member of trust domain "example.org"`)
}

func (s *CATestSuite) TestSignWorkloadX509SVIDChangesSerialNumber() {
	svid1, err := s.ca.SignWorkloadX509SVID(ctx, s.createWorkloadX509SVIDParams())
	s.Require().NoError(err)
	s.Require().Len(svid1, 1)
	svid2, err := s.ca.SignWorkloadX509SVID(ctx, s.createWorkloadX509SVIDParams())
	s.Require().NoError(err)
	s.Require().Len(svid2, 1)
	s.Require().NotEqual(0, svid2[0].SerialNumber.Cmp(svid1[0].SerialNumber))
}

func (s *CATestSuite) TestNoJWTKeySet() {
	s.ca.SetJWTKey(nil)
	_, err := s.ca.SignWorkloadJWTSVID(ctx, s.createJWTSVIDParams(trustDomainExample, 0))
	s.Require().EqualError(err, "JWT key is not available for signing")
}

func (s *CATestSuite) TestSignWorkloadJWTSVIDUsesDefaultTTLIfTTLUnspecified() {
	token, err := s.ca.SignWorkloadJWTSVID(ctx, s.createJWTSVIDParams(trustDomainExample, 0))
	s.Require().NoError(err)
	issuedAt, expiresAt, err := jwtsvid.GetTokenExpiry(token)
	s.Require().NoError(err)
	s.Require().Equal(s.clock.Now(), issuedAt)
	s.Require().Equal(s.clock.Now().Add(DefaultJWTSVIDTTL), expiresAt)
}

func (s *CATestSuite) TestSignWorkloadJWTSVIDUsesTTLIfSpecified() {
	token, err := s.ca.SignWorkloadJWTSVID(ctx, s.createJWTSVIDParams(trustDomainExample, time.Minute+time.Second))
	s.Require().NoError(err)
	issuedAt, expiresAt, err := jwtsvid.GetTokenExpiry(token)
	s.Require().NoError(err)
	s.Require().Equal(s.clock.Now(), issuedAt)
	s.Require().Equal(s.clock.Now().Add(time.Minute+time.Second), expiresAt)
}

func (s *CATestSuite) TestSignWorkloadJWTSVIDCapsTTLToKeyExpiry() {
	token, err := s.ca.SignWorkloadJWTSVID(ctx, s.createJWTSVIDParams(trustDomainExample, time.Hour))
	s.Require().NoError(err)
	issuedAt, expiresAt, err := jwtsvid.GetTokenExpiry(token)
	s.Require().NoError(err)
	s.Require().Equal(s.clock.Now(), issuedAt)
	s.Require().Equal(s.clock.Now().Add(10*time.Minute), expiresAt)
}

func (s *CATestSuite) TestSignWorkloadJWTSVIDValidatesJSR() {
	// spiffe id for wrong trust domain
	_, err := s.ca.SignWorkloadJWTSVID(ctx, s.createJWTSVIDParams(trustDomainFoo, 0))
	s.Require().EqualError(err, `invalid JWT-SVID ID: "spiffe://foo.com/workload" is not a member of trust domain "example.org"`)

	// audience is required
	noAudience := s.createJWTSVIDParams(trustDomainExample, 0)
	noAudience.Audience = nil
	_, err = s.ca.SignWorkloadJWTSVID(ctx, noAudience)
	s.Require().EqualError(err, `invalid JWT-SVID audience: cannot be empty`)
}

func (s *CATestSuite) setX509CA(selfSigned bool) {
	var upstreamChain []*x509.Certificate
	if !selfSigned {
		upstreamChain = []*x509.Certificate{s.caCert, s.upstreamCert}
	}
	s.ca.SetX509CA(&X509CA{
		Signer:        testSigner,
		Certificate:   s.caCert,
		UpstreamChain: upstreamChain,
	})
}

func (s *CATestSuite) setJWTKey() {
	s.ca.SetJWTKey(&JWTKey{
		Signer:   testSigner,
		Kid:      "KID",
		NotAfter: s.clock.Now().Add(10 * time.Minute),
	})
}

func (s *CATestSuite) createWorkloadX509SVIDParams() WorkloadX509SVIDParams {
	return s.createWorkloadX509SVIDParamsInDomain(trustDomainExample)
}

func (s *CATestSuite) createWorkloadX509SVIDParamsInDomain(trustDomain spiffeid.TrustDomain) WorkloadX509SVIDParams {
	return WorkloadX509SVIDParams{
		SPIFFEID:  spiffeid.RequireFromPath(trustDomain, "/workload"),
		PublicKey: testSigner.Public(),
	}
}

func (s *CATestSuite) createJWTSVIDParams(trustDomain spiffeid.TrustDomain, ttl time.Duration) WorkloadJWTSVIDParams {
	return WorkloadJWTSVIDParams{
		SPIFFEID: spiffeid.RequireFromPath(trustDomain, "/workload"),
		Audience: []string{"AUDIENCE"},
		TTL:      ttl,
	}
}

func (s *CATestSuite) createCACertificate(cn string, parent *x509.Certificate) *x509.Certificate {
	return createCACertificate(s.T(), s.clock, cn, parent)
}

func createCACertificate(t *testing.T, clk clock.Clock, cn string, parent *x509.Certificate) *x509.Certificate {
	keyID, err := x509util.GetSubjectKeyID(testSigner.Public())
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			Organization:       []string{"TestOrg"},
			OrganizationalUnit: []string{"TestUnit"},
			CommonName:         cn,
		},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotAfter:              clk.Now().Add(10 * time.Minute),
		SubjectKeyId:          keyID,
	}
	if parent == nil {
		parent = template
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, testSigner.Public(), testSigner)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}
