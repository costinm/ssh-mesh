package util

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
)

var jwtProviders = map[string]*oidc.IDTokenVerifier{}

// Options for JWT authentication:
// - trusted issuers
// - mapping to roles
//
// The end result is a set of claims, including 'roles'.
type AuthConfig struct {
	Issuers []string
}

type JWTAuth struct {
	*AuthConfig
}

func InitJWT(issuers []string) {
	if len(issuers) == 0 {
		return
	}
	for _, i := range issuers {
		provider, err := oidc.NewProvider(context.Background(), i)
		if err != nil {
			slog.Info("Issuer not found, skipping", "iss", i,
				"error", err)
			continue
		}
		verifier := provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
		jwtProviders[i] = verifier
	}
}

// From go-oidc/verify.go
func parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	return payload, nil
}

// "{\"aud\":[\"ssh://localhost:2222\"],\"exp\":1692373809,
// \"iat\":1692370209,
//
//	\"iss\":\"https://container.googleapis.com/v1/...\",
//
// \"kubernetes.io\":{\"namespace\":\"default\",\"serviceaccount\":{\"name\":\"default\",\"uid\":\"a47d63f6-29a4-4e95-94a6-35e39ee6d77c\"}},
//
//	\"nbf\":1692370209,\"sub\":\"system:serviceaccount:default:default\"}"
//
// Stored as kubernetes.io
type k8sClaims struct {
	// Also serviceaccount :{name: default, uid: ....}
	Namespace string
}

func CheckJwt(password string) (tok string, e error) {
	// Validate a JWT as password.
	// Alternative: JWKS_URL and NewRemoteKeySet
	// TODO: init at startup, reuse
	for _, verifier := range jwtProviders {
		idt, err := verifier.Verify(context.Background(), string(password))
		if err == nil {
			// claims - tricky to extract
			j, _ := parseJWT(string(password))
			claims := &k8sClaims{}
			idt.Claims(claims)
			slog.Info("AuthJwt", "token", j, "iss", idt.Issuer,
				"aud", idt.Audience, "sub", idt.Subject,
				"err", err, "claims", claims) // , "tok", string(password))

			return idt.Subject, nil
		} else {
			slog.Info("JWT failed", err, time.Now())
			e = err
		}
	}
	return
}
