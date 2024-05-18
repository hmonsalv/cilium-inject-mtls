ROOT_CN := Panubo Root TEST 2022
INTERMEDIATE_CN := Panubo Intermediate TEST 2022 G1

SERVER_CN := mtls-server.panubo.com
SERVER_SAN := 127.0.0.1,localhost,mtls-server.panubo.com

CLIENT_CN := E40596F3-458E-4FAF-8A08-F539FD6B3575

DEFAULT_CSR      := config/csr_ecdsa.json
ROOT_CSR         := $(DEFAULT_CSR)
INTERMEDIATE_CSR := $(DEFAULT_CSR)
SERVER_CSR       := $(DEFAULT_CSR)
CLIENT_CSR       := $(DEFAULT_CSR)

.PHONY: help root show-root intermediate show-intermediate server show-server client show-clent all clean
help: ## Display this help
	@printf "$$(grep -hE '^\S+:.*##' $(MAKEFILE_LIST) | sed -e 's/:.*##\s*/:/' -e 's/^\(.\+\):\(.*\)/\\x1b[36m\1\\x1b[m:\2/' | column -c2 -t -s :)\n"

certs/:
	mkdir certs

certs/root_ca.json: certs/ config/csr_ecdsa.json
	jq '. += {"ca":{"expiry":"87600h"}}' $(ROOT_CSR) | cfssl gencert -config=config/config.json -profile=CA -cn="$(ROOT_CN)" -initca - | tee certs/root_ca.json

certs/ca.crt: certs/root_ca.json
	jq -r .cert certs/root_ca.json > certs/ca.crt

certs/ca.key: certs/root_ca.json
	jq -r .key certs/root_ca.json > certs/ca.key

root: certs/ca.crt certs/ca.key ## Generate root CA

show-root: certs/ca.crt ## Show openssl output for root certificate
	openssl x509 -noout -text -in certs/ca.crt

certs/intermediate_ca.json: config/config.json config/csr_ecdsa.json certs/ca.crt certs/ca.key 
	cfssl gencert -config=config/config.json -ca=certs/ca.crt -ca-key=certs/ca.key \
		-cn="$(INTERMEDIATE_CN)" -profile=CA $(INTERMEDIATE_CSR) | tee certs/intermediate_ca.json

certs/intermediate.crt: certs/intermediate_ca.json
	jq -r .cert certs/intermediate_ca.json > certs/intermediate.crt

certs/intermediate.key: certs/intermediate_ca.json
	jq -r .key certs/intermediate_ca.json > certs/intermediate.key

intermediate: certs/intermediate.crt certs/intermediate.key ## Generate intermediate CA

show-intermediate: certs/intermediate.crt ## Show openssl output for intermediate certificate
	openssl x509 -noout -text -in certs/intermediate.crt

certs/server.json: certs/intermediate.crt certs/intermediate.key
	cfssl gencert -config=config/config.json -ca=certs/intermediate.crt -ca-key=certs/intermediate.key -cn="$(SERVER_CN)" -hostname="$(SERVER_SAN)" -profile=server $(SERVER_CSR) | tee certs/server.json

certs/server.crt: certs/server.json
	jq -r .cert certs/server.json > certs/server.crt

certs/server.key: certs/server.json
	jq -r .key certs/server.json > certs/server.key

# Server bundle of key, certificate and intermediate certificate
certs/server.pem: certs/server.key certs/server.crt certs/intermediate.crt
	cat certs/server.key certs/server.crt certs/intermediate.crt > certs/server.pem

server: certs/server.crt certs/server.key certs/server.pem ## Generate server CA

show-server: certs/server.crt ## Show openssl output for server certificate
	openssl x509 -noout -text -in certs/server.crt

certs/client.json: certs/intermediate.crt certs/intermediate.key
	cfssl gencert -config=config/config.json -ca=certs/intermediate.crt -ca-key=certs/intermediate.key -cn="$(CLIENT_CN)" -profile=client $(CLIENT_CSR) | tee certs/client.json

certs/client.crt: certs/client.json
	jq -r .cert certs/client.json > certs/client.crt

certs/client.key: certs/client.json
	jq -r .key certs/client.json > certs/client.key

certs/client.pem: certs/client.key certs/client.crt certs/intermediate.crt
	cat certs/client.key certs/client.crt certs/intermediate.crt > certs/client.pem

client: certs/client.crt certs/client.key certs/client.pem ## Generate client CA

show-client: certs/client.crt ## Show openssl output for client certificate
	openssl x509 -noout -text -in certs/client.crt

all: client server ## Generate all

clean: ## Remove all generated certificates and keys
	rm -rf certs/
