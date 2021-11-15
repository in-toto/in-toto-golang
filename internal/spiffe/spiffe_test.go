package spiffe

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	td    = spiffeid.RequireTrustDomainFromString("example.org")
	fooID = td.NewID("foo")
)

func assertX509SVID(tb testing.TB, sd SVIDDetails, spiffeID spiffeid.ID, certificates []*x509.Certificate, intermediates []*x509.Certificate) {
	assert.NotEmpty(tb, spiffeID)
	assert.Equal(tb, certificates[0], sd.Certificate)
	assert.Equal(tb, intermediates, sd.Intermediates)
	assert.NotEmpty(tb, sd.PrivateKey)
}

func assertInTotoKey(tb testing.TB, key intoto.Key, svid *x509svid.SVID) {
	assert.NotNil(tb, key.KeyID, "keyID is empty.")
	assert.Equal(tb, []string{"sha256", "sha512"}, key.KeyIDHashAlgorithms)
	assert.Equal(tb, "ecdsa", key.KeyType)
	assert.Equal(tb, "ecdsa-sha2-nistp256", key.Scheme)
	cerBytes, keyBytes, _ := svid.Marshal()
	keyData, _ := pem.Decode(keyBytes)
	certData, _ := pem.Decode(cerBytes)
	assert.Equal(tb, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Bytes: keyData.Bytes, Type: "PRIVATE KEY"}))), key.KeyVal.Private)
	privKey, _ := x509.ParseCertificate(certData.Bytes)
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(privKey.PublicKey)
	assert.Equal(tb, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Bytes: pubKeyBytes, Type: "PUBLIC KEY"}))), key.KeyVal.Public)
	assert.Equal(tb, string(pem.EncodeToMemory(&pem.Block{Bytes: svid.Certificates[0].Raw, Type: "CERTIFICATE"})), key.KeyVal.Certificate)

}

func makeX509SVIDs(ca *test.CA, ids ...spiffeid.ID) []*x509svid.SVID {
	svids := []*x509svid.SVID{}
	for _, id := range ids {
		svids = append(svids, ca.CreateX509SVID(id))
	}
	return svids
}

func getSVIDs(t *testing.T, badInput bool) *test.X509SVIDResponse {
	ca := test.NewCA(t, td)
	var svids []*x509svid.SVID
	if badInput {
		svids = makeX509SVIDsNoPrivateKey(ca, fooID)
	} else {
		svids = makeX509SVIDs(ca, fooID)
	}

	resp := &test.X509SVIDResponse{
		Bundle: ca.X509Bundle(),
		SVIDs:  svids,
	}
	return resp
}

func makeX509SVIDsNoPrivateKey(ca *test.CA, ids ...spiffeid.ID) []*x509svid.SVID {
	svids := []*x509svid.SVID{}
	for _, id := range ids {
		svids = append(svids, ca.CreateX509SVIDNoPrivateKey(id))
	}
	return svids
}

func TestNewClient(t *testing.T) {

	wl := test.NewWorkloadAPI(t)
	defer wl.Stop()
	spireClient, err := NewClient(context.Background(), wl.Addr())
	require.NoError(t, err)
	defer spireClient.Close()
	assert.Nil(t, err, "Unexpected error!")
	assert.NotNil(t, spireClient, "Unexpected error getting client")
}

func TestGetSVIDNoPrivateKey(t *testing.T) {

	wl := test.NewWorkloadAPI(t)
	defer wl.Stop()
	spireClient, err := NewClient(context.Background(), wl.Addr())
	require.NoError(t, err)
	defer spireClient.Close()
	resp := getSVIDs(t, true)
	wl.SetX509SVIDResponse(resp)

	svidDetail, err := GetSVID(context.Background(), spireClient)
	assert.Equal(t, SVIDDetails{PrivateKey: nil, Certificate: nil, Intermediates: nil}, svidDetail)
	assert.Error(t, err)
}

func TestGetSVID(t *testing.T) {
	wl := test.NewWorkloadAPI(t)
	defer wl.Stop()
	spireClient, err := NewClient(context.Background(), wl.Addr())
	require.NoError(t, err)
	defer spireClient.Close()

	resp := getSVIDs(t, false)
	wl.SetX509SVIDResponse(resp)

	svidDetail, err := GetSVID(context.Background(), spireClient)
	require.NoError(t, err)
	assertX509SVID(t, svidDetail, fooID, resp.SVIDs[0].Certificates, resp.SVIDs[0].Certificates[1:])
}

func TestSVIDDetails_IntotoKey(t *testing.T) {
	wl := test.NewWorkloadAPI(t)
	defer wl.Stop()
	spireClient, err := NewClient(context.Background(), wl.Addr())
	require.NoError(t, err)
	defer spireClient.Close()

	resp := getSVIDs(t, false)
	wl.SetX509SVIDResponse(resp)

	svidDetail, err := GetSVID(context.Background(), spireClient)

	require.NoError(t, err)

	key, err := svidDetail.InTotoKey()
	assert.Nil(t, err, "Unexpected error!")
	assertInTotoKey(t, key, resp.SVIDs[0])
}

func TestSVIDDetails_BadIntotoKey(t *testing.T) {
	wl := test.NewWorkloadAPI(t)
	defer wl.Stop()
	spireClient, err := NewClient(context.Background(), wl.Addr())
	require.NoError(t, err)
	defer spireClient.Close()

	resp := getSVIDs(t, false)
	wl.SetX509SVIDResponse(resp)

	svidDetail, err := GetSVID(context.Background(), spireClient)

	require.NoError(t, err)

	svidDetail.PrivateKey = nil

	key, err := svidDetail.InTotoKey()
	assert.Equal(t, intoto.Key{KeyID: "", KeyIDHashAlgorithms: nil, KeyType: "",
		Scheme: "", KeyVal: intoto.KeyVal{Private: "",
			Public: "", Certificate: ""}}, key)
	assert.Error(t, err)
}
