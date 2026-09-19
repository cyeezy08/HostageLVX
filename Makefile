# Makefile — local dev convenience
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST ?= dist

.PHONY: build build-all clean test vet fmt lint docker install-smoke demo demo-record

build:
	go build -ldflags="$(LDFLAGS)" -o hostage .

demo: build
	./hostage -demo

demo-record: build
	@if command -v asciinema >/dev/null 2>&1; then \
		asciinema rec --command './hostage -demo' demo.cast; \
	else \
		echo 'asciinema is not installed. Run: go build -o hostage . && ./hostage -demo'; \
		./hostage -demo; \
	fi

build-all: clean
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/hostage-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/hostage-linux-arm64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/hostage-windows-amd64.exe .
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/hostage-darwin-arm64 .
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/hostage-darwin-amd64 .
	cd $(DIST) && sha256sum hostage-* | tee checksums.sha256

test:
	go test ./... -timeout 60s -v

vet:
	go vet ./...

fmt:
	gofmt -s -w .

lint:
	golangci-lint run --timeout 5m

docker:
	docker build -t hostage .

install-smoke: build
	cp hostage /usr/local/bin/hostage
	hostage -V
	hostage -fingerprints | head -10

clean:
	rm -rf $(DIST) hostage hostage.exe
