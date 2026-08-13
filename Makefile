.PHONY: build test lint clean test-integration

build:
	go build -o bin/templar cmd/templar/main.go

test:
	go test -v ./...

test-integration:
	go test -v -tags=integration ./tests/integration/...

lint:
	golangci-lint run

clean:
	rm -rf bin/
