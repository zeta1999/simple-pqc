// PQC mTLS client (Track 1 / Track 3).
//
// Connects with a client cert, pins the hybrid PQC KEM X25519MLKEM768, and
// asserts the negotiated group is post-quantum -- exiting non-zero otherwise.
//
//	env: URL (default https://127.0.0.1:8443/), CERT_DIR (default ../certs)
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"simplepqc/common"
)

func main() {
	url := common.Env("URL", "https://127.0.0.1:8443/")
	certDir := common.Env("CERT_DIR", "../certs")

	pool, err := common.LoadPool(certDir + "/ca.crt")
	if err != nil {
		log.Fatalf("load CA: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certDir+"/client.crt", certDir+"/client.key")
	if err != nil {
		log.Fatalf("load client cert: %v", err)
	}

	cfg := &tls.Config{
		RootCAs:          pool,
		Certificates:     []tls.Certificate{cert},
		ServerName:       "localhost",
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{common.WantGroup},
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg},
		Timeout:   10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	cs := resp.TLS
	if cs == nil || cs.CurveID != common.WantGroup {
		got := "none"
		if cs != nil {
			got = common.GroupName(cs.CurveID)
		}
		log.Fatalf("FAIL: negotiated non-PQC KEX (%s), wanted %s", got, common.GroupName(common.WantGroup))
	}

	body, _ := io.ReadAll(resp.Body)
	log.Printf("OK  status=%s  kex=%s", resp.Status, common.GroupName(cs.CurveID))
	fmt.Print(string(body))
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}
