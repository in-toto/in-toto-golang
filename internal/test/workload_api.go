package test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var noIdentityError = status.Error(codes.PermissionDenied, "no identity issued")

type WorkloadAPI struct {
	tb        testing.TB
	wg        sync.WaitGroup
	addr      string
	server    *grpc.Server
	mu        sync.Mutex
	x509Resp  *workload.X509SVIDResponse
	x509Chans map[chan *workload.X509SVIDResponse]struct{}
}

func NewWorkloadAPI(tb testing.TB) *WorkloadAPI {
	w := &WorkloadAPI{
		x509Chans: make(map[chan *workload.X509SVIDResponse]struct{}),
	}

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(tb, err)

	server := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(server, &workloadAPIWrapper{w: w})

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		_ = server.Serve(listener)
	}()

	w.addr = fmt.Sprintf("%s://%s", listener.Addr().Network(), listener.Addr().String())
	tb.Logf("WorkloadAPI address: %s", w.addr)
	w.server = server
	return w
}

func (w *WorkloadAPI) Stop() {
	w.server.Stop()
	w.wg.Wait()
}

func (w *WorkloadAPI) Addr() string {
	return w.addr
}

func (w *WorkloadAPI) SetX509SVIDResponse(r *X509SVIDResponse) {
	var resp *workload.X509SVIDResponse
	if r != nil {
		resp = r.ToProto(w.tb)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	w.x509Resp = resp

	for ch := range w.x509Chans {
		select {
		case ch <- resp:
		default:
			<-ch
			ch <- resp
		}
	}
}

func concatRawCertsFromCerts(certs []*x509.Certificate) []byte {
	var rawCerts []byte
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.Raw...)
	}
	return rawCerts
}

func (r *X509SVIDResponse) ToProto(tb testing.TB) *workload.X509SVIDResponse {
	var bundle []byte
	if r.Bundle != nil {
		bundle = concatRawCertsFromCerts(r.Bundle.X509Authorities())
	}

	pb := &workload.X509SVIDResponse{
		FederatedBundles: make(map[string][]byte),
	}
	for _, svid := range r.SVIDs {
		var keyDER []byte
		if svid.PrivateKey != nil {
			var err error
			keyDER, err = x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
			require.NoError(tb, err)
		}
		pb.Svids = append(pb.Svids, &workload.X509SVID{
			SpiffeId:    svid.ID.String(),
			X509Svid:    concatRawCertsFromCerts(svid.Certificates),
			X509SvidKey: keyDER,
			Bundle:      bundle,
		})
	}
	for _, v := range r.FederatedBundles {
		pb.FederatedBundles[v.TrustDomain().IDString()] = concatRawCertsFromCerts(v.X509Authorities())
	}

	return pb
}

type workloadAPIWrapper struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	w *WorkloadAPI
}

func (w *workloadAPIWrapper) FetchX509SVID(req *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	return w.w.fetchX509SVID(req, stream)
}

type X509SVIDResponse struct {
	SVIDs            []*x509svid.SVID
	Bundle           *x509bundle.Bundle
	FederatedBundles []*x509bundle.Bundle
}

func (w *WorkloadAPI) fetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if err := checkHeader(stream.Context()); err != nil {
		return err
	}
	ch := make(chan *workload.X509SVIDResponse, 1)
	w.mu.Lock()
	w.x509Chans[ch] = struct{}{}
	resp := w.x509Resp
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		delete(w.x509Chans, ch)
		w.mu.Unlock()
	}()

	sendResp := func(resp *workload.X509SVIDResponse) error {
		if resp == nil {
			return noIdentityError
		}
		return stream.Send(resp)
	}

	if err := sendResp(resp); err != nil {
		return err
	}
	for {
		select {
		case resp := <-ch:
			if err := sendResp(resp); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func checkHeader(ctx context.Context) error {
	return checkMetadata(ctx, "workload.spiffe.io", "true")
}

func checkMetadata(ctx context.Context, key, value string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return errors.New("request does not contain metadata")
	}
	values := md.Get(key)
	if len(value) == 0 {
		return fmt.Errorf("request metadata does not contain %q value", key)
	}
	if values[0] != value {
		return fmt.Errorf("request metadata %q value is %q; expected %q", key, values[0], value)
	}
	return nil
}
