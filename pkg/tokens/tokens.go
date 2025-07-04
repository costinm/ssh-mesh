package tokens

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Tokens handle authentication using tokens instead of certificates.
// It covers the most common cases:
// - exec
// - GCP-like MDS
// - WIP: OAuth2 refresh tokens
// - WIP: cert-based self-signed tokens
//
// Main use case for tokens is 'over http2' tunnels, when direct connectivity is not possible.
// Second use case is for exchanging a platform credential to SSH and TLS certificates.
//
// For SSH and Istio mesh, certificates are the 'native' authentication.
//
// SSH can also handle tokens in the 'password' field - by setting a TokenVerifier on server and TokenSource on
// client.

// TokenExec is the config for an exec-based token source, using a subset
// of kubeconfig. In k8s, pkg/client/auth/exec is handling this, it has a cache
// and other fancy features.
//
// In particular, KUBERNETES_EXEC_INFO may hold 'spec.interactive' and 'spec.cluster'.
// The output from K8S command is also a json, with 'status.token' and optional status.ClientCertificateData,
// ClientKeyData, ExpirationTimestamp
type TokenExec struct {
	Command string       `json:"command,omitempty"`
	Args    []string     `json:"args,omitempty"`
	Env     []ExecEnvVar `json:"env,omitempty"`
}

type ExecEnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (e *TokenExec) GetToken(ctx context.Context, aud string) (string, error) {
	if e.Command == "" {
		e.Command = "gcloud"
		e.Args = []string{"auth", "print-access-token", "--audience"}
	}

	args := append(e.Args, aud)
	cmd := exec.Command(e.Command, args...)

	for _, env := range e.Env {
		cmd.Env = append(cmd.Env, env.Name+"="+env.Value)
	}

	bb := &bytes.Buffer{}
	cmd.Stdout = bb
	cmd.Run()

	return bb.String(), nil
}

type MDS struct {
	Addr string
}

func (m *MDS) GetToken(ctx context.Context, aud string) (string, error) {

	if m.Addr == "" {
		m.Addr = os.Getenv("GCE_METADATA_HOST")
	}
	if m.Addr == "" {
		m.Addr = "169.254.169.254"
	}
	if !strings.Contains(m.Addr, "/") {
		m.Addr = "http://" + m.Addr + "/computeMetadata/v1/"
	}

	if aud == "" || strings.Contains(aud, "googleapis.com") {
		uri := "instance/service-accounts/default/token"
		tok, err := m.MetadataGet(uri)
		if err != nil {
			return "", err
		}
		return tok, nil
	}

	uri := fmt.Sprintf("instance/service-accounts/default/identity?audience=%s", aud)
	//if s.UseMDSFullToken { // TODO: test the difference
	uri = uri + "&format=full"
	//}
	tok, err := m.MetadataGet(uri)
	if err != nil {
		return "", err
	}
	return tok, nil
}

func (m *MDS) MetadataGet(path string) (string, error) {
	ctx, cf := context.WithTimeout(context.Background(), 3*time.Second)
	defer cf()

	mdsHost := m.Addr

	req, err := http.NewRequestWithContext(ctx, "GET", mdsHost+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server responeded with code=%d %s", resp.StatusCode, resp.Status)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), err
}
