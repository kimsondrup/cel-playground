// Copyright 2025 Undistro Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build oracle

package oracle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WebhookCall is one admission request the apiserver actually delivered.
type WebhookCall struct {
	Path        string
	UID         string
	Operation   string
	Resource    metav1.GroupVersionResource
	Namespace   string
	Name        string
	Username    string
	UserGroups  []string
	DryRun      bool
	ObjectLabel map[string]string
}

// WebhookServer is an HTTPS admission webhook running inside the test process.
// It is the ground truth for match-condition evaluation: whether the apiserver
// decided a webhook matches is not something you can infer from the admission
// outcome, but it is exactly what "did my handler get called" answers.
type WebhookServer struct {
	URL      string
	CABundle []byte

	srv *http.Server
	ln  net.Listener

	mu    sync.Mutex
	calls []WebhookCall
	// deny is consulted for every request; returning a non-empty string denies
	// with that message. It is guarded because the apiserver may still have a
	// request in flight when a test moves on and sets the next one.
	deny func(path string, req *admissionv1.AdmissionRequest) string
}

// SetDeny installs the decision the handler returns for subsequent requests.
func (ws *WebhookServer) SetDeny(deny func(path string, req *admissionv1.AdmissionRequest) string) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	ws.deny = deny
}

// StartWebhookServer brings up a TLS listener on 127.0.0.1 with a freshly
// generated self-signed certificate, and returns the server together with the
// CA bundle the apiserver needs in order to trust it.
func StartWebhookServer() (*WebhookServer, error) {
	certPEM, keyPEM, err := selfSignedCert()
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading generated keypair: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listening: %w", err)
	}

	ws := &WebhookServer{
		ln:       ln,
		CABundle: certPEM,
		URL:      fmt.Sprintf("https://127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", ws.handle)
	ws.srv = &http.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}

	go func() {
		// ServeTLS with an empty cert/key pair uses TLSConfig.Certificates.
		_ = ws.srv.ServeTLS(ln, "", "")
	}()
	return ws, nil
}

// Stop shuts the server down.
func (ws *WebhookServer) Stop() error {
	if ws == nil || ws.srv == nil {
		return nil
	}
	return ws.srv.Close()
}

// Calls returns a snapshot of everything the apiserver has sent so far.
func (ws *WebhookServer) Calls() []WebhookCall {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	out := make([]WebhookCall, len(ws.calls))
	copy(out, ws.calls)
	return out
}

// CallsTo returns the calls delivered to one path.
func (ws *WebhookServer) CallsTo(path string) []WebhookCall {
	var out []WebhookCall
	for _, c := range ws.Calls() {
		if c.Path == path {
			out = append(out, c)
		}
	}
	return out
}

// Reset forgets all recorded calls.
func (ws *WebhookServer) Reset() {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	ws.calls = nil
}

func (ws *WebhookServer) handle(w http.ResponseWriter, r *http.Request) {
	var review admissionv1.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		http.Error(w, fmt.Sprintf("decoding AdmissionReview: %v", err), http.StatusBadRequest)
		return
	}
	req := review.Request
	if req == nil {
		http.Error(w, "AdmissionReview has no request", http.StatusBadRequest)
		return
	}

	call := WebhookCall{
		Path:       r.URL.Path,
		UID:        string(req.UID),
		Operation:  string(req.Operation),
		Resource:   req.Resource,
		Namespace:  req.Namespace,
		Name:       req.Name,
		Username:   req.UserInfo.Username,
		UserGroups: req.UserInfo.Groups,
		DryRun:     req.DryRun != nil && *req.DryRun,
	}
	// Pull labels out of the raw object so tests can key off them.
	if len(req.Object.Raw) > 0 {
		var obj struct {
			Metadata struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
		}
		if json.Unmarshal(req.Object.Raw, &obj) == nil {
			call.ObjectLabel = obj.Metadata.Labels
		}
	}

	ws.mu.Lock()
	ws.calls = append(ws.calls, call)
	ws.mu.Unlock()

	ws.mu.Lock()
	deny := ws.deny
	ws.mu.Unlock()

	resp := admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}
	if deny != nil {
		if msg := deny(r.URL.Path, req); msg != "" {
			resp.Allowed = false
			resp.Result = &metav1.Status{Message: msg, Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden}
		}
	}

	out := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Response: &resp,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// selfSignedCert produces a certificate that is its own CA, valid for
// 127.0.0.1, which is what lets the apiserver dial the in-process handler over
// a url: clientConfig with caBundle set to the same PEM.
func selfSignedCert() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "cel-playground-oracle-webhook"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
