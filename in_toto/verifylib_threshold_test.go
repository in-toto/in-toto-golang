package in_toto

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

func keyFromPrivAndCert(t *testing.T, priv crypto.PrivateKey, certPEM []byte) Key {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	var k Key
	if err := k.LoadKeyReaderDefaults(bytes.NewReader(privPEM)); err != nil {
		t.Fatalf("load key: %v", err)
	}
	if certPEM != nil {
		k.KeyVal.Certificate = string(certPEM)
	}
	return k
}

func signedLinkForStep(t *testing.T, name string, k Key) Metadata {
	t.Helper()
	mb := &Metablock{Signed: Link{Type: "link", Name: name, Materials: map[string]HashObj{}, Products: map[string]HashObj{}}}
	if err := mb.Sign(k); err != nil {
		t.Fatalf("sign link: %v", err)
	}
	return mb
}

// A step whose functionaries mix pubkeys and certificate constraints must
// verify deterministically regardless of link map iteration order.
func TestVerifyLinkSignatureThesholdsMixedFunctionaries(t *testing.T) {
	validity := time.Hour
	rootCert, _, rootKey, err := createSelfSignedCA(&x509.Certificate{Subject: pkix.Name{CommonName: "Root CA"}, MaxPathLen: 1}, x509.Ed25519, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intCert, _, intKey, err := createCA(&x509.Certificate{Subject: pkix.Name{CommonName: "Int CA"}, MaxPathLen: 0}, rootCert, rootKey, x509.Ed25519, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, leafCertPEM, leafPriv, err := createEndEntityCert(&x509.Certificate{Subject: pkix.Name{CommonName: "functionary", Organization: []string{"example"}}}, intCert, intKey, x509.Ed25519, validity)
	if err != nil {
		t.Fatal(err)
	}
	_, _, pubPriv, err := createEndEntityCert(&x509.Certificate{Subject: pkix.Name{CommonName: "pub"}}, intCert, intKey, x509.Ed25519, validity)
	if err != nil {
		t.Fatal(err)
	}

	certKey := keyFromPrivAndCert(t, leafPriv, leafCertPEM)
	pubKey := keyFromPrivAndCert(t, pubPriv, nil)

	layout := Layout{
		Type: "layout",
		Keys: map[string]Key{pubKey.KeyID: pubKey},
		Steps: []Step{{
			Type:                   "step",
			Threshold:              2,
			PubKeys:                []string{pubKey.KeyID},
			CertificateConstraints: []CertificateConstraint{{CommonName: "*", DNSNames: []string{"*"}, Emails: []string{"*"}, Organizations: []string{"*"}, URIs: []string{"*"}, Roots: []string{"*"}}},
			SupplyChainItem:        SupplyChainItem{Name: "foo"},
		}},
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	intPool := x509.NewCertPool()
	intPool.AddCert(intCert)

	stepsMetadata := map[string]map[string]Metadata{
		"foo": {pubKey.KeyID: signedLinkForStep(t, "foo", pubKey), certKey.KeyID: signedLinkForStep(t, "foo", certKey)},
	}

	// Run repeatedly because the pre-fix bug surfaced only for some map orders.
	for i := 0; i < 20; i++ {
		result, err := VerifyLinkSignatureThesholds(layout, stepsMetadata, rootPool, intPool)
		if err != nil {
			t.Fatalf("run %d: unexpected error: %v", i, err)
		}
		if len(result["foo"]) != 2 {
			t.Fatalf("run %d: expected 2 verified links, got %d", i, len(result["foo"]))
		}
	}
}
