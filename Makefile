GOPATH=$(shell go env GOPATH)

.PHONY: default
default: lint test

.PHONY: lint
lint:
	go get github.com/golangci/golangci-lint/cmd/golangci-lint@v1.37.0
	$(GOPATH)/bin/golangci-lint run -e gosec ./...
	go fmt ./...
	go mod tidy

.PHONY: test
test:
	go test --race internal/s11n/*.go 
	go test --race command.go query.go authority.go encoding*.go transaction*.go


.PHONY: setup
setup:
	sh setup.sh
