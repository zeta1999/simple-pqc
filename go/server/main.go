// PQC mTLS server (Track 1 / Track 3).
//
// Requires TLS 1.3 with the hybrid post-quantum KEM X25519MLKEM768, mutual
// auth against the demo CA, and REFUSES any connection whose negotiated key
// exchange group is not post-quantum -- silent classical downgrade is the
// failure mode we defend against.
//
//	env: ADDR (default :8443), CERT_DIR (default ../certs)
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"

	"simplepqc/common"
)

func main() {
	addr := common.Env("ADDR", ":8443")
	certDir := common.Env("CERT_DIR", "../certs")

	pool, err := common.LoadPool(certDir + "/ca.crt")
	if err != nil {
		log.Fatalf("load CA: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certDir+"/server.crt", certDir+"/server.key")
	if err != nil {
		log.Fatalf("load server cert: %v", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
		// Pin the hybrid PQC KEM only: a classical-only client shares no
		// group with us and its handshake fails (proves the negative test).
		CurvePreferences: []tls.CurveID{common.WantGroup},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cs := r.TLS
		if cs.CurveID != common.WantGroup {
			log.Printf("REFUSED %s: non-PQC KEX %s", r.RemoteAddr, common.GroupName(cs.CurveID))
			http.Error(w, "post-quantum KEX required", http.StatusUpgradeRequired)
			return
		}
		peer := "<none>"
		if len(cs.PeerCertificates) > 0 {
			peer = cs.PeerCertificates[0].Subject.CommonName
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, fmt.Sprintf(
			`{"ok":true,"impl":"go","kex":%q,"tls":"1.3","peer_cn":%q}`+"\n",
			common.GroupName(cs.CurveID), peer))
		log.Printf("served %s  kex=%s  peer_cn=%s", r.RemoteAddr, common.GroupName(cs.CurveID), peer)
	})

	srv := &http.Server{Addr: addr, TLSConfig: cfg, Handler: mux}
	log.Printf("go PQC mTLS server on %s  (require %s)", addr, common.GroupName(common.WantGroup))
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
