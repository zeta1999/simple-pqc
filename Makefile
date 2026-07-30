# simple-pqc demos. See PLAN.md for the full roadmap.
.DEFAULT_GOAL := help
SHELL := /bin/bash

.PHONY: help certs go rust build run-go run-rust interop prove prove-neg ssh mldsa channel test docker k3s-probe clean

help: ## show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
	 awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n",$$1,$$2}'

certs: ## generate the Ed25519 mini-CA + server/client certs (Track 0)
	./scripts/gen-ca.sh

go: certs ## build the Go endpoints
	cd go && go build -o ./bin/pqc-server ./server && go build -o ./bin/pqc-client ./client

rust: certs ## build the Rust endpoints
	cd rust && cargo build

build: go rust ## build everything

run-go: go ## run Go server (:8443) then Go client once
	@CERT_DIR=$(PWD)/certs ADDR=127.0.0.1:8443 ./go/bin/pqc-server & \
	 SRV=$$!; sleep 2; \
	 CERT_DIR=$(PWD)/certs URL=https://127.0.0.1:8443/ ./go/bin/pqc-client; \
	 kill $$SRV 2>/dev/null

run-rust: rust ## run Rust server (:9443) then Rust client once
	@CERT_DIR=$(PWD)/certs ADDR=127.0.0.1:9443 ./rust/target/debug/pqc-server & \
	 SRV=$$!; sleep 2; \
	 CERT_DIR=$(PWD)/certs HOST=127.0.0.1 PORT=9443 ./rust/target/debug/pqc-client; \
	 kill $$SRV 2>/dev/null

interop: certs ## Track 3: full cross-language interop matrix
	./scripts/interop.sh

prove: ## prove a running endpoint negotiates PQC KEX: make prove PORT=8443
	./scripts/prove-pqc.sh 127.0.0.1 $(or $(PORT),8443)

prove-neg: ## prove a classical-only client is refused: make prove-neg PORT=8443
	./scripts/prove-pqc.sh 127.0.0.1 $(or $(PORT),8443) --negative

ssh: ## Track S: PQC SSH to a non-root sshd (mlkem768x25519-sha256)
	./scripts/ssh-pqc-demo.sh

mldsa: ## Track 5 (experimental): fully-PQC mTLS with ML-DSA-65 certs
	./scripts/mldsa-tls-demo.sh

channel: ## Track 4: simple-network PQC channel (ML-DSA-65 mutual auth) over TCP
	cd channel && cargo run

test: ## run every locally-verifiable experiment (E5-E8) with a summary
	./scripts/run-all.sh

docker: ## Track 6: build multi-arch images (needs a running Docker daemon)
	./scripts/docker-build.sh $(ARGS)

k3s-probe: ## Track K1: probe a k3s node for PQC KEM (needs a cluster): make k3s-probe HOST=1.2.3.4
	./scripts/k3s-probe.sh $(or $(HOST),127.0.0.1)

clean: ## remove generated certs and build artifacts
	rm -rf certs certs-mldsa go/bin rust/target channel/target ssh-demo
