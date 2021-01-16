
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
MAKEFLAGS += --silent

build: modules
	@mkdir -p bin
	@go build -o=./bin/in-toto

modules:
	@go mod tidy

clean:
	@rm -rf ./bin

clean-certs:
	@rm ./certs/*.pem ./certs/*.srl

test: go-test test-verify test-run

test-verify: build
	@./bin/in-toto verify

test-run: build
	@./bin/in-toto run

go-test:
	@go test ./...

generate-test-certs: intermediate_cert

root-cert:
	#Create Root Key
	@openssl ecparam  -name prime256v1 -genkey -noout -out ./certs/root_key.pem
	#Create Root Cert
	@openssl req -subj "/C=US/ST=/L=/O=SPIRE/OU=/CN=root/" -days 3650 -x509 -new \
	-key "./certs/root_key.pem" -out "./certs/root_cert.pem" \
	-config ./certs/openssl.cnf \
	-extensions v3-req


intermediate_cert: root-cert
	#Create intermediate key
	@openssl ecparam -name prime256v1 -genkey -noout -out ./certs/intermediate_key.pem
	#Generate intermediate CSR
	@openssl req -subj "/C=US/ST=/L=/O=SPIRE/OU=/CN=intermediate/" -new \
	-key ./certs/intermediate_key.pem \
	-out ./certs/intermediate_csr.pem \
	-config ./certs/openssl.cnf \
	-extensions v3-intermediate
	#Sign Intermediate CSR Using Root Certificate
	@openssl x509 -days 3650 -req \
	-CAcreateserial \
	-CA ./certs/root_cert.pem \
	-CAkey ./certs/root_key.pem \
	-in ./certs/intermediate_csr.pem \
	-out ./certs/intermediate_cert.pem \
	-extfile ./certs/openssl.cnf \
	-extensions v3-intermediate
	@openssl verify -CAfile ./certs/root_cert.pem ./certs/intermediate_cert.pem

leaf_cert: intermediate_cert
	@cat ./certs/openssl.cnf | sed -e 's#STEP#step1#' > ./certs/openssl.cnf.tmp
	#Generate leaf signing key
	@openssl ecparam -name prime256v1 -genkey -noout -out ./certs/step1_key.pem
	#Generate leaf CSR
	@openssl req -subj "/C=US/ST=/L=/O=SPIRE/OU=/CN=step1/" -new \
	-key ./certs/step1_key.pem \
	-out ./certs/step1_csr.pem \
	-config ./certs/openssl.cnf.tmp \
	-extensions v3-leaf
	#Sign leaf CSR Using intermediate Certificate
	@openssl x509 -days 1 -req \
	-CAcreateserial \
	-CA ./certs/intermediate_cert.pem \
	-CAkey ./certs/intermediate_key.pem \
	-in ./certs/step1_csr.pem \
	-out ./certs/step1_cert.pem \
	-extfile ./certs/openssl.cnf.tmp \
	-extensions v3-leaf
	@rm ./certs/openssl.cnf.tmp
	


.PHONY: help
all: help
help: Makefile
	@echo
	@echo " Choose a command run in in-toto-golang:"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo