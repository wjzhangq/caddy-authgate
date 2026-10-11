MODULE  := github.com/wjzhangq/caddy-authgate
ARCHES  := amd64 arm64
OSES    := linux darwin windows

.PHONY: test lint build build-linux build-all e2e clean

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

build-all:
	@for os in $(OSES); do for arch in $(ARCHES); do \
		ext=; [ $$os = windows ] && ext=.exe; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch xcaddy build \
			--with $(MODULE)=. --output dist/caddy-authgate-$$os-$$arch$$ext || exit 1; \
	done; done

e2e: build
	./scripts/e2e.sh dist/caddy

clean:
	rm -rf dist
