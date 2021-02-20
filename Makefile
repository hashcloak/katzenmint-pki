
.PHONY: default
default: lint test

.PHONY: lint
lint:
	go get github.com/golangci/golangci-lint/cmd/golangci-lint@v1.37.0
	golangci-lint run ./...
	go fmt ./...
	go mod tidy

.PHONY: test
test: 
	go test ./...