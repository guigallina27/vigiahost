# Build, testes e pacotes do VigiaHost. Empacotar e testar com -race exige Linux (laboratório ou CI).
VERSION    ?= 0.0.0-dev
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo desconhecido)
# Data do commit, e não a do build, para que o binário seja reprodutível.
DATE       ?= $(shell git log -1 --format=%cI 2>/dev/null || echo desconhecida)
GOARCH     ?= amd64
# Contato dos pacotes ainda não definido; .invalid é um domínio reservado que nunca resolve.
MAINTAINER ?= Mantenedores do VigiaHost <mantenedores@vigiahost.invalid>

PKG     := github.com/guigallina27/vigiahost
LDFLAGS := -s -w -X $(PKG)/internal/version.Version=$(VERSION) \
           -X $(PKG)/internal/version.Commit=$(COMMIT) \
           -X $(PKG)/internal/version.Date=$(DATE)

.PHONY: build test test-race fuzz vet vuln package clean

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) GOAMD64=v1 \
		go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o dist/$(GOARCH)/ ./cmd/vigiahost ./cmd/vigiahost-executor

test:
	go test ./...

test-race:
	CGO_ENABLED=1 go test -race ./...

fuzz:
	go test -run='^$$' -fuzz=FuzzCodecRead -fuzztime=30s ./internal/ipc

vet:
	go vet ./...
	test -z "$$(gofmt -l .)"

vuln:
	go tool govulncheck ./...

# O nfpm não expande variáveis nos caminhos de origem; os binários da arquitetura vão para dist/stage.
package: build
	rm -rf dist/stage && mkdir -p dist/stage && cp dist/$(GOARCH)/* dist/stage/
	for fmt in deb rpm; do \
		VERSION=$(VERSION) GOARCH=$(GOARCH) MAINTAINER="$(MAINTAINER)" \
			go tool nfpm package -f packaging/nfpm.yaml -p $$fmt -t dist/ || exit 1; \
	done

clean:
	rm -rf dist
