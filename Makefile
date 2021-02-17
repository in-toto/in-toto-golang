
-include .env

#VERSION := $(shell git describe --tags)
#BUILD := $(shell git rev-parse --short HEAD)
PROJECTNAME := in-toto-go

# Go related variables.
#GOBASE := $(shell pwd)
#GOPATH := $(GOBASE)/vendor:$(GOBASE)
#GOBIN := $(GOBASE)/bin
#GOFILES := $(wildcard *.go)

# Use linker flags to provide version/build settings
#LDFLAGS=-ldflags "-X=main.Version=$(VERSION) -X=main.Build=$(BUILD)"

# Make is verbose in Linux. Make it silent.
#MAKEFLAGS += --silent

#Common Certificate Attributes
TRUST_DOMAIN_FQDN := example.com
DEFAULT_BITS := 2048
DEFAULT_MD := sha512
ORGANIZATIONAL_UNIT := example
ORGANIZATION := example
ROOT_DAYS := 3650
INTERMEDIATE_DAYS := 3650
LEAF_DAYS := 1

#Template Location
OPENSSL_TMPL := ./certs/openssl.cnf.tmpl

build: modules
	@mkdir -p bin
	@go build -o=./bin/in-toto

modules:
	@go mod tidy

clean:
	@rm -rf ./bin

clean-certs:
	@rm ./certs/*.pem ./certs/*.srl ./certs/*.cnf

test: go-test test-verify test-run

test-verify: build
	@./bin/in-toto verify

test-run: build
	#Step 1
	@./bin/in-toto run -n write-code -c ./certs/example.com.write-code.cert.pem -k ./certs/example.com.write-code.key.pem -p ./test/data/foo.py -- "-c" "echo hello > ./test/data/foo.py"
	#Step 2
	@./bin/in-toto run -n package -c ./certs/example.com.package.cert.pem -k ./certs/example.com.package.key.pem -m ./test/data/foo.py -p ./test/data/foo.tar.gz -- tar zcvf ./test/data/foo.py

	



go-test:
	@go test ./...

generate-test-certs: intermediate_cert

root-cert:
	$(call generate_openssl_conf,root)
	#Create Root Key
	@openssl genrsa -out ./certs/root.key.pem
	#Create Root Cert
	@openssl req -subj "/C=/ST=/L=/O=$(ORGANIZATION)/OU=$(ORGANIZATIONAL_UNIT)CN=root/" -days $(ROOT_DAYS) -x509 -new \
	-key "./certs/root.key.pem" -out "./certs/root.cert.pem" \
	-config ./certs/$(TRUST_DOMAIN_FQDN).root.openssl.cnf \
	-extensions v3-root


intermediate_cert: root-cert
	$(call generate_openssl_conf,intermediate)
	#Create intermediate key
	@openssl genrsa -out ./certs/$(TRUST_DOMAIN_FQDN).intermediate.key.pem
	#Generate intermediate CSR
	@openssl req -subj "/C=/ST=/L=/O=$(ORGANIZATION)/OU=$(ORGANIZATIONAL_UNIT)CN=$(TRUST_DOMAIN_FQDN)" -new \
	-key ./certs/$(TRUST_DOMAIN_FQDN).intermediate.key.pem \
	-out ./certs/$(TRUST_DOMAIN_FQDN).intermediate.csr.pem \
	-config ./certs/$(TRUST_DOMAIN_FQDN).intermediate.openssl.cnf \
	-extensions v3-intermediate
	#Sign Intermediate CSR Using Root Certificate
	@openssl x509 -days $(INTERMEDIATE_DAYS) -req \
	-CAcreateserial \
	-CA ./certs/root.cert.pem \
	-CAkey ./certs/root.key.pem \
	-in ./certs/$(TRUST_DOMAIN_FQDN).intermediate.csr.pem \
	-out ./certs/$(TRUST_DOMAIN_FQDN).intermediate.cert.pem \
	-extfile ./certs/$(TRUST_DOMAIN_FQDN).intermediate.openssl.cnf \
	-extensions v3-intermediate
	@openssl verify -CAfile ./certs/root.cert.pem ./certs/$(TRUST_DOMAIN_FQDN).intermediate.cert.pem

leaf_certs: intermediate_cert
	$(call gernerate_leaf_cert,write-code)
	$(call gernerate_leaf_cert,package)

define gernerate_leaf_cert
	$(call generate_openssl_conf,$(1))
	#Generate leaf signing key
	@openssl genrsa -out ./certs/$(TRUST_DOMAIN_FQDN).$(1).key.pem
	#Generate leaf CSR
	openssl req -new \
	-key ./certs/$(TRUST_DOMAIN_FQDN).$(1).key.pem \
	-out ./certs/$(TRUST_DOMAIN_FQDN).$(1).csr.pem \
	-config ./certs/$(TRUST_DOMAIN_FQDN).$(1).openssl.cnf \
	-extensions v3-leaf
	#Sign leaf CSR Using intermediate Certificate
	@openssl x509 -days $(LEAF_DAYS) -req \
	-CAcreateserial \
	-CA ./certs/$(TRUST_DOMAIN_FQDN).intermediate.cert.pem \
	-CAkey ./certs/$(TRUST_DOMAIN_FQDN).intermediate.key.pem \
	-in ./certs/$(TRUST_DOMAIN_FQDN).$(1).csr.pem \
	-out ./certs/$(TRUST_DOMAIN_FQDN).$(1).cert.pem \
	-extfile ./certs/$(TRUST_DOMAIN_FQDN).$(1).openssl.cnf \
	-extensions v3-leaf
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