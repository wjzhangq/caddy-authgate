MODULE  := github.com/wjzhangq/caddy-authgate
ARCHES  := amd64 arm64

.PHONY: test lint build build-linux e2e clean

test:
	go vet ./...
	go test -race -cover ./...

lint:
	golangci-lint run

build:
	xcaddy build --with $(MODULE)=. --output dist/caddy

build-linux:
	@for arch in $(ARCHES); do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch xcaddy build \
			--with $(MODULE)=. --output dist/caddy-authgate-linux-$$arch || exit 1; \
	done

e2e: build
	./scripts/e2e.sh dist/caddy

clean:
	rm -rf dist
