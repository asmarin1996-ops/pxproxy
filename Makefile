BINARY := pxproxy
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build linux verify test clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 .

test:
	go test -race ./...

verify: test
	gofmt -l . && go vet ./...

clean:
	rm -rf dist $(BINARY) $(BINARY).exe
