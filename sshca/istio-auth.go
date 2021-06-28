package sshca

import "strings"

// Authenticate using Istio mTLS, for gRPC and HTTP
// TODO: move to separate module, deps free

// Envoy generates a header like:
// x-forwarded-client-cert: \
//    By=spiffe://cluster.local/ns/ssh-ca/sa/default;\
//    Hash=881...3da93b;\
//    Subject="";URI=spiffe://cluster.local/ns/sshd/sa/default

// https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
//

//

func ParseXFCC(val string) map[string]string {
	// Each element represents a proxy in the path
	elems := strings.Split(val, ",")

	last := elems[len(elems) - 1]

	m := map[string]string{}
	kvp := strings.Split(last, ";")
	for _, v := range kvp {
		// Note that values may include escaped quotes, and may be quoted if they include , or ;
		// This is not used in istio
		kv := strings.SplitN(v, "=", 2)
		m[kv[0]] = kv[1]
	}
	return m
}
