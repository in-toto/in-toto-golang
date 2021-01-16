
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
	@mkdir bin
	@go build -o=./bin/in-toto

modules:
	@go mod tidy

clean:
	@rm -rf ./bin

.PHONY: help
all: help
help: Makefile
	@echo
	@echo " Choose a command run in in-toto-golang:"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo