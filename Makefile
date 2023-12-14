ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
BIN_DIR := $(abspath $(ROOT_DIR)/bin)
IMG ?= audit-scanner:latest

GOLANGCI_LINT_VER := v1.54.2
GOLANGCI_LINT_BIN := golangci-lint
GOLANGCI_LINT := $(BIN_DIR)/$(GOLANGCI_LINT_BIN)

all: build

$(GOLANGCI_LINT): ## Install golangci-lint.
	GOBIN=$(BIN_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VER)

fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet ./...

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run

.PHONY: unit-tests
unit-tests: fmt vet ## Run unit tests.
	go test ./cmd/... ./internal/... -test.v -coverprofile cover.out

build: fmt vet lint ## Build audit-scanner binary.
	go build -o bin/audit-scanner .

.PHONY: docker-build
docker-build: unit-tests
	DOCKER_BUILDKIT=1 docker build -t ${IMG} .
