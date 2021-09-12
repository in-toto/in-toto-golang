# Common Certificate Attributes
TRUST_DOMAIN_FQDN := example.com
DEFAULT_BITS := 2048
DEFAULT_MD := sha512
ORGANIZATIONAL_UNIT := example
ORGANIZATION := example
ROOT_DAYS := 3650
INTERMEDIATE_DAYS := 3650
LEAF_DAYS := 1
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)


# Template Locations
OPENSSL_TMPL := ./certs/openssl.cnf.tmpl
LAYOUT_TMPL := ./certs/layout.tmpl

build: modules
	@mkdir -p bin
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
	-o ./bin/in-toto ./cmd/in-toto

modules:
	@go mod tidy

clean: clean-certs clean-test-files spiffe-infra-down
	@rm -rf ./bin

clean-certs:
	@rm -rf ./certs/*.pem ./certs/*.srl ./certs/*.cnf

clean-test-files:
	@rm -rf ./test/tmp
	@rm -rf ./untar.link
	@rm -rf ./.srl

test: go-test test-verify test-spiffe-verify

go-test:
	@go test ./...

test-sign: build generate_layout
	# Running test-sign
	cd ./test/tmp; ../../bin/in-toto sign -f ./test.layout -k ../../certs/example.com.layout.key.pem -o ./signed.layout

test-record: build generate_layout
    # Running record start
	cd ./test/tmp; ../../bin/in-toto record start -n write-code -c ../../certs/example.com.write-code.cert.pem -k ../../certs/example.com.write-code.key.pem -d .
    # Record running step
	cd ./test/tmp; echo goodbye > foo.py
	# Running record stop
	cd ./test/tmp; ../../bin/in-toto record stop -n write-code -c ../../certs/example.com.write-code.cert.pem -p foo.py -k ../../certs/example.com.write-code.key.pem -d .

test-run: build generate_layout
	# Running write code step
	cd ./test/tmp; ../../bin/in-toto run -n write-code -c ../../certs/example.com.write-code.cert.pem -k ../../certs/example.com.write-code.key.pem -p foo.py -d . -- /bin/sh -c "echo hello > foo.py"
	# Running package step
	cd ./test/tmp; ../../bin/in-toto run -n package -c ../../certs/example.com.package.cert.pem -k ../../certs/example.com.package.key.pem -m foo.py -p foo.tar.gz -d . -- tar zcvf foo.tar.gz foo.py

test-verify: test-sign test-run
	# Running test verify
	cd ./test/tmp; ../../bin/in-toto verify -l ./signed.layout -k ../../certs/example.com.layout.cert.pem -i ../../certs/example.com.intermediate.cert.pem -d .

test-spiffe-run: test-spiffe-sign
	# Running write code step
	docker exec -u 1000 -w /test/tmp -it intoto-runner in-toto run --spiffe-workload-api-path unix:///run/spire/sockets/agent.sock -n write-code -p foo.py -d . -- /bin/sh -c "echo hello > foo.py"
	# Running package step
	docker exec -u 1001 -w /test/tmp -it intoto-runner in-toto run --spiffe-workload-api-path unix:///run/spire/sockets/agent.sock -n package -m foo.py -p foo.tar.gz -d . -- tar zcvf foo.tar.gz foo.py

test-spiffe-verify: test-spiffe-sign test-spiffe-run
	# Running test verify
	docker exec -it -w /test/tmp intoto-runner /bin/in-toto verify -l ./spiffe.signed.layout -k ./layout-svid.pem -d .

test-spiffe-sign: build spiffe-test-generate-layout
	docker exec -it -w /test/tmp intoto-runner /bin/in-toto sign -f ./spiffe.test.layout -k ./layout-key.pem -o ./spiffe.signed.layout

spiffe-test-generate-layout: spiffe-infra-up
	# Get key layout from the root cert
	$(eval rootca := $(shell ./bin/in-toto key layout ./test/tmp/layout-bundle.pem | sed -e 's/\\n/\\\\n/g'))
	cat $(LAYOUT_TMPL) | sed -e 's#{{ROOTCA}}#$(rootca)#' > ./test/tmp/spiffe.test.layout
	docker-compose -f ./test-infra/docker-compose.yaml up -d intoto-runner

spiffe-infra-up: build
	@mkdir -p ./test/tmp
	@chmod 777 ./test/tmp
	./test-infra/infra-up.sh
	./test-infra/mint-cert.sh layout

spiffe-infra-down:
	./test-infra/infra-down.sh

generate_layout: build leaf_certs
	@mkdir -p ./test/tmp
	# get key layout from the root cert
	$(eval rootca := $(shell ./bin/in-toto key layout ./certs/root.cert.pem | sed -e 's/\\n/\\\\n/g'))
	cat $(LAYOUT_TMPL) | sed -e 's#{{ROOTCA}}#$(rootca)#' > ./test/tmp/test.layout

root-cert:
	# Generate root cert openssl conf file
	$(call generate_openssl_conf,root)

	# Create Root Key
	@openssl genrsa -out ./certs/root.key.pem

	# Create Root Cert
	@openssl req -subj "/C=/ST=/L=/O=$(ORGANIZATION)/OU=$(ORGANIZATIONAL_UNIT)CN=root/" -days $(ROOT_DAYS) -x509 -new \
	-key "./certs/root.key.pem" -out "./certs/root.cert.pem" \
	-config ./certs/$(TRUST_DOMAIN_FQDN).root.openssl.cnf \
	-extensions v3-root

intermediate_cert: root-cert
	# Generate intermediate cert openssl conf file
	$(call generate_openssl_conf,intermediate)

	# Create intermediate key
	@openssl genrsa -out ./certs/$(TRUST_DOMAIN_FQDN).intermediate.key.pem

	# Generate intermediate CSR
	@openssl req -subj "/C=/ST=/L=/O=$(ORGANIZATION)/OU=$(ORGANIZATIONAL_UNIT)CN=$(TRUST_DOMAIN_FQDN)" -new \
	-key ./certs/$(TRUST_DOMAIN_FQDN).intermediate.key.pem \
	-out ./certs/$(TRUST_DOMAIN_FQDN).intermediate.csr.pem \
	-config ./certs/$(TRUST_DOMAIN_FQDN).intermediate.openssl.cnf \
	-extensions v3-intermediate

	# Sign Intermediate CSR Using Root Certificate
	@openssl x509 -days $(INTERMEDIATE_DAYS) -req \
	-CAcreateserial \
	-CA ./certs/root.cert.pem \
	-CAkey ./certs/root.key.pem \
	-in ./certs/$(TRUST_DOMAIN_FQDN).intermediate.csr.pem \
	-out ./certs/$(TRUST_DOMAIN_FQDN).intermediate.cert.pem \
	-extfile ./certs/$(TRUST_DOMAIN_FQDN).intermediate.openssl.cnf \
	-extensions v3-intermediate

	# Verify intermediate cert was signed by root cert
	@openssl verify -CAfile ./certs/root.cert.pem ./certs/$(TRUST_DOMAIN_FQDN).intermediate.cert.pem

leaf_certs: intermediate_cert
	$(call generate_leaf_cert,layout)
	$(call generate_leaf_cert,write-code)
	$(call generate_leaf_cert,package)

define generate_leaf_cert
	# Generate leaf cert openssl conf file
	$(call generate_openssl_conf,$(1))

	# Generate leaf signing key
	@openssl genrsa -out ./certs/$(TRUST_DOMAIN_FQDN).$(1).key.pem

	# Generate leaf CSR
	openssl req -new \
	-key ./certs/$(TRUST_DOMAIN_FQDN).$(1).key.pem \
	-out ./certs/$(TRUST_DOMAIN_FQDN).$(1).csr.pem \
	-config ./certs/$(TRUST_DOMAIN_FQDN).$(1).openssl.cnf \
	-extensions v3-leaf

	# Sign leaf CSR Using intermediate Certificate
	@openssl x509 -days $(LEAF_DAYS) -req \
	-CAcreateserial \
	-CA ./certs/$(TRUST_DOMAIN_FQDN).intermediate.cert.pem \
	-CAkey ./certs/$(TRUST_DOMAIN_FQDN).intermediate.key.pem \
	-in ./certs/$(TRUST_DOMAIN_FQDN).$(1).csr.pem \
	-out ./certs/$(TRUST_DOMAIN_FQDN).$(1).cert.pem \
	-extfile ./certs/$(TRUST_DOMAIN_FQDN).$(1).openssl.cnf \
	-extensions v3-leaf

	# Create cert bundle for trust domain
	cat ./certs/root.cert.pem ./certs/$(TRUST_DOMAIN_FQDN).intermediate.cert.pem > ./certs/$(TRUST_DOMAIN_FQDN).bundle.cert.pem

	# Verify leaf cert chain
	@openssl verify -CAfile ./certs/$(TRUST_DOMAIN_FQDN).bundle.cert.pem ./certs/$(TRUST_DOMAIN_FQDN).$(1).cert.pem
endef

define generate_openssl_conf
	@cat $(OPENSSL_TMPL) | sed -e 's/{{TRUST_DOMAIN_FQDN}}/$(TRUST_DOMAIN_FQDN)/'  | \
	sed -e 's/{{ORGANIZATIONAL_UNIT}}/$(ORGANIZATIONAL_UNIT)/' | \
	sed -e 's/{{ORGANIZATION}}/$(ORGANIZATION)/' | \
	sed -e 's/{{DEFUALT_BITS}}/$(DEFAULT_BITS)/' | \
	sed -e 's/{{DEFAULT_MD}}/$(DEFAULT_MD)/' | \
	sed -e 's/{{SPIFFE_PATH}}/$(1)/' > certs/$(TRUST_DOMAIN_FQDN).$(1).openssl.cnf
endef

.PHONY: help
all: help
help: Makefile
	@echo
	@echo " Choose a command run in in-toto-golang:"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo
