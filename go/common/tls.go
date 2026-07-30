// Package common holds shared PQC mTLS helpers for the Go demo endpoints.
//
// PQC property demonstrated: post-quantum KEY EXCHANGE via the hybrid
// X25519MLKEM768 group (Go's default since 1.24; here we PIN and ASSERT it).
// Authentication stays classical (Ed25519 certs) -- see scripts/gen-ca.sh.
package common

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// WantGroup is the hybrid post-quantum KEM group we require on both ends.
// IANA codepoint 0x11EC (4588).
const WantGroup = tls.X25519MLKEM768

// Env returns the env var or a default.
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// LoadPool reads a PEM CA bundle into a cert pool.
func LoadPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", caFile)
	}
	return pool, nil
}

// GroupName renders a CurveID as "NAME (0xHEX)" for the groups we care about.
func GroupName(id tls.CurveID) string {
	names := map[tls.CurveID]string{
		tls.X25519MLKEM768: "X25519MLKEM768",
		tls.X25519:         "X25519",
		tls.CurveP256:      "secp256r1",
		tls.CurveP384:      "secp384r1",
		tls.CurveP521:      "secp521r1",
	}
	if n, ok := names[id]; ok {
		return fmt.Sprintf("%s (0x%04x)", n, uint16(id))
	}
	return fmt.Sprintf("0x%04x", uint16(id))
}
