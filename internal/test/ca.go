package test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
)

type CA struct {
	tb     testing.TB
	td     spiffeid.TrustDomain
	parent *CA
	cert   *x509.Certificate
	key    crypto.Signer
	jwtKey crypto.Signer
	jwtKid string
}

type CertificateOption interface {
	apply(*x509.Certificate)
}

type certificateOption func(*x509.Certificate)

func (co certificateOption) apply(c *x509.Certificate) {
	co(c)
}

// NewEC256Key returns an ECDSA key over the P256 curve
func NewEC256Key(tb testing.TB) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)
	return key
}

// NewKeyID returns a random id useful for identifying keys
func NewKeyID(tb testing.TB) string {
	choices := make([]byte, 32)
	_, err := rand.Read(choices)
	require.NoError(tb, err)
	return keyIDFromBytes(choices)
}

func keyIDFromBytes(choices []byte) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf := new(bytes.Buffer)
	for _, choice := range choices {
		buf.WriteByte(alphabet[int(choice)%len(alphabet)])
	}
	return buf.String()
}

func NewCA(tb testing.TB, td spiffeid.TrustDomain) *CA {
	cert, key := CreateCACertificate(tb, nil, nil)
	return &CA{
		tb:     tb,
		td:     td,
		cert:   cert,
		key:    key,
		jwtKey: NewEC256Key(tb),
		jwtKid: NewKeyID(tb),
	}
}

func (ca *CA) ChildCA(options ...CertificateOption) *CA {
	cert, key := CreateCACertificate(ca.tb, ca.cert, ca.key, options...)
	return &CA{
		tb:     ca.tb,
		parent: ca,
		cert:   cert,
		key:    key,
		jwtKey: NewEC256Key(ca.tb),
		jwtKid: NewKeyID(ca.tb),
	}
}

func (ca *CA) CreateX509SVID(id spiffeid.ID, options ...CertificateOption) *x509svid.SVID {
	cert, key := CreateX509SVID(ca.tb, ca.cert, ca.key, id, options...)
	return &x509svid.SVID{
		ID:           id,
		Certificates: append([]*x509.Certificate{cert}, ca.chain(false)...),
		PrivateKey:   key,
	}
}

func (ca *CA) CreateX509SVIDNoPrivateKey(id spiffeid.ID, options ...CertificateOption) *x509svid.SVID {
	cert, _ := CreateX509SVID(ca.tb, ca.cert, ca.key, id, options...)
	return &x509svid.SVID{
		ID:           id,
		Certificates: append([]*x509.Certificate{cert}, ca.chain(false)...),
	}
}

func (ca *CA) CreateX509Certificate(options ...CertificateOption) ([]*x509.Certificate, crypto.Signer) {
	cert, key := CreateX509Certificate(ca.tb, ca.cert, ca.key, options...)
	return append([]*x509.Certificate{cert}, ca.chain(false)...), key
}

func (ca *CA) X509Authorities() []*x509.Certificate {
	root := ca
	for root.parent != nil {
		root = root.parent
	}
	return []*x509.Certificate{root.cert}
}

func (ca *CA) Bundle() *spiffebundle.Bundle {
	bundle := spiffebundle.New(ca.td)
	bundle.SetX509Authorities(ca.X509Authorities())
	return bundle
}

func (ca *CA) X509Bundle() *x509bundle.Bundle {
	return x509bundle.FromX509Authorities(ca.td, ca.X509Authorities())
}

func CreateCACertificate(tb testing.TB, parent *x509.Certificate, parentKey crypto.Signer, options ...CertificateOption) (*x509.Certificate, crypto.Signer) {
	now := time.Now()
	serial := NewSerial(tb)
	key := NewEC256Key(tb)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("CA %x", serial),
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
	}

	applyOptions(tmpl, options...)

	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	return CreateCertificate(tb, tmpl, parent, key.Public(), parentKey), key
}

func CreateX509Certificate(tb testing.TB, parent *x509.Certificate, parentKey crypto.Signer, options ...CertificateOption) (*x509.Certificate, crypto.Signer) {
	now := time.Now()
	serial := NewSerial(tb)
	key := NewEC256Key(tb)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("X509-Certificate %x", serial),
		},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	applyOptions(tmpl, options...)

	return CreateCertificate(tb, tmpl, parent, key.Public(), parentKey), key
}

func CreateX509SVID(tb testing.TB, parent *x509.Certificate, parentKey crypto.Signer, id spiffeid.ID, options ...CertificateOption) (*x509.Certificate, crypto.Signer) {
	serial := NewSerial(tb)
	options = append(options,
		WithSerial(serial),
		WithKeyUsage(x509.KeyUsageDigitalSignature),
		WithSubject(pkix.Name{
			CommonName: fmt.Sprintf("X509-SVID %x", serial),
		}),
		WithURIs(id.URL()))

	return CreateX509Certificate(tb, parent, parentKey, options...)
}

func CreateCertificate(tb testing.TB, tmpl, parent *x509.Certificate, pub, priv interface{}) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	require.NoError(tb, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(tb, err)
	return cert
}

func NewSerial(tb testing.TB) *big.Int {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	require.NoError(tb, err)
	return new(big.Int).SetBytes(b)
}

func WithSerial(serial *big.Int) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.SerialNumber = serial
	})
}

func WithKeyUsage(keyUsage x509.KeyUsage) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.KeyUsage = keyUsage
	})
}

func WithURIs(uris ...*url.URL) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.URIs = uris
	})
}

func WithSubject(subject pkix.Name) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.Subject = subject
	})
}

func applyOptions(c *x509.Certificate, options ...CertificateOption) {
	for _, opt := range options {
		opt.apply(c)
	}
}

func (ca *CA) chain(includeRoot bool) []*x509.Certificate {
	chain := []*x509.Certificate{}
	next := ca
	for next != nil {
		if includeRoot || next.parent != nil {
			chain = append(chain, next.cert)
		}
		next = next.parent
	}
	return chain
}
