# Common Certificate Attributes
TRUST_DOMAIN_FQDN := example.com
DEFAULT_BITS := 2048
DEFAULT_MD := sha512
ORGANIZATIONAL_UNIT := example
ORGANIZATION := example
ROOT_DAYS := 3650
INTERMEDIATE_DAYS := 3650
LEAF_DAYS := 1

# Template Locations
OPENSSL_TMPL := ./test/data/openssl.cnf.tmpl
LAYOUT_TMPL := ./test/data/layout.tmpl

build: modules
	@mkdir -p bin
	@go build -o ./bin/in-toto ./cmd/in-toto

modules:
	@go mod tidy

clean: clean-test/data clean-test-files
	@rm -rf ./bin

clean-test/data:
	@rm -rf ./test/data/*.pem ./test/data/*.srl ./test/data/*.cnf

clean-test-files:
	@rm -rf ./test/tmp
	@rm -rf ./untar.link
	@rm -rf ./.srl

test: go-test test-verify

go-test:
	@go test ./...

test-sign: build generate_layout
	# Running test-sign
	@./bin/in-toto sign -f ./test/tmp/test.layout -k ./test/data/example.com.layout.key.pem -o ./test/tmp/signed.layout

test-run: build generate_layout
	# Running write code step
	@./bin/in-toto run -n write-code -c ./test/data/example.com.write-code.cert.pem -k ./test/data/example.com.write-code.key.pem -p ./test/tmp/foo.py -d ./test/tmp -- /bin/sh -c "echo hello > ./test/tmp/foo.py"
	# Running package step
	@./bin/in-toto run -n package -c ./test/data/example.com.package.cert.pem -k ./test/data/example.com.package.key.pem -m ./test/tmp/foo.py -p ./test/tmp/foo.tar.gz -d ./test/tmp -- tar zcvf ./test/tmp/foo.tar.gz ./test/tmp/foo.py

test-verify: test-sign test-run
	# Running test verify
	@./bin/in-toto verify -l ./test/tmp/signed.layout -k ./test/data/example.com.layout.cert.pem -i ./test/data/example.com.intermediate.cert.pem -d ./test/tmp

generate_layout: leaf_test/data
	@mkdir -p ./test/tmp
	$(eval rootid := $(shell ./bin/in-toto key id ./test/data/root.cert.pem))
	$(eval rootca := $(shell ./bin/in-toto key layout ./test/data/root.cert.pem | sed -e 's/\\n/\\\\n/g'))
	@cat $(LAYOUT_TMPL) | sed -e 's#{{ROOTCA}}#$(rootca)#' -e 's#{{ROOTID}}#$(rootid)#' > ./test/tmp/test.layout

root-cert:
	# Generate root cert openssl conf file
	$(call generate_openssl_conf,root)

	# Create Root Key
	@openssl genrsa -out ./test/data/root.key.pem

	# Create Root Cert
	@openssl req -subj "/C=/ST=/L=/O=$(ORGANIZATION)/OU=$(ORGANIZATIONAL_UNIT)CN=root/" -days $(ROOT_DAYS) -x509 -new \
	-key "./test/data/root.key.pem" -out "./test/data/root.cert.pem" \
	-config ./test/data/$(TRUST_DOMAIN_FQDN).root.openssl.cnf \
	-extensions v3-root

intermediate_cert: root-cert
	# Generate intermediate cert openssl conf file
	$(call generate_openssl_conf,intermediate)

	# Create intermediate key
	@openssl genrsa -out ./test/data/$(TRUST_DOMAIN_FQDN).intermediate.key.pem

	# Generate intermediate CSR
	@openssl req -subj "/C=/ST=/L=/O=$(ORGANIZATION)/OU=$(ORGANIZATIONAL_UNIT)CN=$(TRUST_DOMAIN_FQDN)" -new \
	-key ./test/data/$(TRUST_DOMAIN_FQDN).intermediate.key.pem \
	-out ./test/data/$(TRUST_DOMAIN_FQDN).intermediate.csr.pem \
	-config ./test/data/$(TRUST_DOMAIN_FQDN).intermediate.openssl.cnf \
	-extensions v3-intermediate

	# Sign Intermediate CSR Using Root Certificate
	@openssl x509 -days $(INTERMEDIATE_DAYS) -req \
	-CAcreateserial \
	-CA ./test/data/root.cert.pem \
	-CAkey ./test/data/root.key.pem \
	-in ./test/data/$(TRUST_DOMAIN_FQDN).intermediate.csr.pem \
	-out ./test/data/$(TRUST_DOMAIN_FQDN).intermediate.cert.pem \
	-extfile ./test/data/$(TRUST_DOMAIN_FQDN).intermediate.openssl.cnf \
	-extensions v3-intermediate

	# Verify intermediate cert was signed by root cert
	@openssl verify -CAfile ./test/data/root.cert.pem ./test/data/$(TRUST_DOMAIN_FQDN).intermediate.cert.pem

leaf_test/data: intermediate_cert
	$(call generate_leaf_cert,layout)
	$(call generate_leaf_cert,write-code)
	$(call generate_leaf_cert,package)

define generate_leaf_cert
	# Generate leaf cert openssl conf file
	$(call generate_openssl_conf,$(1))

	# Generate leaf signing key
	@openssl genrsa -out ./test/data/$(TRUST_DOMAIN_FQDN).$(1).key.pem

	# Generate leaf CSR
	openssl req -new \
	-key ./test/data/$(TRUST_DOMAIN_FQDN).$(1).key.pem \
	-out ./test/data/$(TRUST_DOMAIN_FQDN).$(1).csr.pem \
	-config ./test/data/$(TRUST_DOMAIN_FQDN).$(1).openssl.cnf \
	-extensions v3-leaf

	# Sign leaf CSR Using intermediate Certificate
	@openssl x509 -days $(LEAF_DAYS) -req \
	-CAcreateserial \
	-CA ./test/data/$(TRUST_DOMAIN_FQDN).intermediate.cert.pem \
	-CAkey ./test/data/$(TRUST_DOMAIN_FQDN).intermediate.key.pem \
	-in ./test/data/$(TRUST_DOMAIN_FQDN).$(1).csr.pem \
	-out ./test/data/$(TRUST_DOMAIN_FQDN).$(1).cert.pem \
	-extfile ./test/data/$(TRUST_DOMAIN_FQDN).$(1).openssl.cnf \
	-extensions v3-leaf

	# Create cert bundle for trust domain
	cat ./test/data/root.cert.pem ./test/data/$(TRUST_DOMAIN_FQDN).intermediate.cert.pem > ./test/data/$(TRUST_DOMAIN_FQDN).bundle.cert.pem

	# Verify leaf cert chain
	@openssl verify -CAfile ./test/data/$(TRUST_DOMAIN_FQDN).bundle.cert.pem ./test/data/$(TRUST_DOMAIN_FQDN).$(1).cert.pem
endef

define generate_openssl_conf
	@cat $(OPENSSL_TMPL) | sed -e 's/{{TRUST_DOMAIN_FQDN}}/$(TRUST_DOMAIN_FQDN)/'  | \
	sed -e 's/{{ORGANIZATIONAL_UNIT}}/$(ORGANIZATIONAL_UNIT)/' | \
	sed -e 's/{{ORGANIZATION}}/$(ORGANIZATION)/' | \
	sed -e 's/{{DEFUALT_BITS}}/$(DEFAULT_BITS)/' | \
	sed -e 's/{{DEFAULT_MD}}/$(DEFAULT_MD)/' | \
	sed -e 's/{{SPIFFE_PATH}}/$(1)/' > test/data/$(TRUST_DOMAIN_FQDN).$(1).openssl.cnf
endef

.PHONY: help
all: help
help: Makefile
	@echo
	@echo " Choose a command run in in-toto-golang:"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo
