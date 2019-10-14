BUILD_DIR 		:= build

.DEFAULT_GOAL := build

.PHONY: init
init:
	go get github.com/golangci/golangci-lint/cmd/golangci-lint@v1.17.1
	go get -u github.com/onsi/ginkgo/ginkgo
	go get -u github.com/modocache/gover
	go mod download

.PHONY: lint
lint:
	golangci-lint run --config golangci.yml

.PHONY: test
test:
	$(GOPATH)/bin/ginkgo -r --randomizeAllSpecs --randomizeSuites --failOnPending --cover --trace --progress --compilers=2

.PHONY: format
format:
	go fmt $(go list)
	goimports -e -w -d $(shell find . -type f -name '*.go' -print)

.PHONY: cover
cover:
	$(GOPATH)/bin/gover . coverage.txt