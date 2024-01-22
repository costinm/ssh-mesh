package util

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"log"
)

const tokenFile = "/var/run/secrets/tokens/ssh/token"

type MDS struct {
	MDSBase string

	// TODO: cache, etc
	// TODO: plug other types of tokens and

	Client *http.Client

	// TODO: stats
}

// NewMDSClient returns a client for an GCP MDS-like server.
//
// It can return JWT tokens for the 'primary' service account, as well
// as metadata.
func NewMDSClient(mdsBase string) *MDS {
	if mdsBase == "" {
		mdsBase = os.Getenv("GCE_METADATA_HOST")
	}
	if mdsBase == "" {
		mdsBase = "169.254.169.254"
	}
	if !strings.Contains(mdsBase, "/") {
		mdsBase = "http://" + mdsBase + "/computeMetadata/v1/"
	}
	mds := &MDS{
		MDSBase: mdsBase,
		Client:  http.DefaultClient,
	}

	return mds
}

// POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/service-<GCP project number>@gcp-sa-meshdataplane.iam.gserviceaccount.com:generateAccessToken
// Content-Type: application/json
// Authorization: Bearer <federated token>
//
//	{
//	 "Delegates": [],
//	 "Scope": [
//	     https://www.googleapis.com/auth/cloud-platform
//	 ],
//	}
func (mds *MDS) GetToken(ctx1 context.Context, aud string) (string, error) {
	// TODO: check well-known files
	if _, err := os.Stat(tokenFile); err == nil {
		data, err := ioutil.ReadFile(tokenFile)
		if err != nil {
			log.Println("Failed to read token file", err)
		} else {
			return string(data), nil
		}
	}

	ctx, cf := context.WithTimeout(ctx1, 5*time.Second)
	defer cf()
	req, err := http.NewRequestWithContext(ctx, "GET", mds.MDSBase+fmt.Sprintf("instance/service-accounts/default/identity?audience=%s", aud), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := mds.Client.Do(req)
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
