GOPATH=$(shell go env GOPATH)

.PHONY: default
default: lint test

.PHONY: lint
lint:
	go get github.com/golangci/golangci-lint/cmd/golangci-lint@v1.37.0
	$(GOPATH)/bin/golangci-lint run -e gosec ./...
	go fmt ./...
	go mod tidy

# added -race in future (badger fatal error: checkptr: pointer arithmetic result points to invalid allocation)
# https://github.com/golang/go/issues/40917
.PHONY: test
test:
	go test s11n/*.go 
	go test command.go query.go authority.go encoding*.go transaction*.go state*.go app*.go


.PHONY: setup
setup:
	sh setup.sh

.PHONY: build
build:
	go build -o katzenmint cmd/katzenmint.go
