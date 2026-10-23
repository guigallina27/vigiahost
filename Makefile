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

.PHONY: build web web-check generate check-generated test test-race fuzz vet vuln package clean

# Binários Go; embutem o que houver em internal/webui/dist (rode make web antes para incluir a interface).
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) GOAMD64=v1 \
		go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o dist/$(GOARCH)/ ./cmd/vigiahost ./cmd/vigiahost-executor

# Interface React: instala exatamente o lockfile e gera o build em internal/webui/dist.
web:
	cd web && pnpm install --frozen-lockfile && pnpm run build

# Lint, tipos e testes unitários da interface (os de acessibilidade usam Playwright: cd web && pnpm test:a11y).
web-check:
	cd web && pnpm install --frozen-lockfile && pnpm run lint && pnpm run typecheck && pnpm run test

# Código gerado do contrato api/openapi.yaml: tipos e servidor Go, tipos TypeScript.
generate:
	go generate ./internal/api
	cd web && pnpm run gen:api

# Falha se o código gerado não corresponder ao contrato (usado no CI).
check-generated: generate
	git diff --exit-code -- internal/api web/src/api/schema.d.ts

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

# O pacote sempre leva a interface. O nfpm não expande variáveis nos caminhos de origem; os binários vão para dist/stage.
# A arquitetura chega ao nfpm como PKG_ARCH, e GOARCH é esvaziado: o make exporta variáveis da linha de comando, e com
# GOARCH=arm64 o próprio nfpm seria compilado para arm64 e não rodaria no host.
package: web build
	rm -rf dist/stage && mkdir -p dist/stage && cp dist/$(GOARCH)/* dist/stage/
	for fmt in deb rpm; do \
		VERSION=$(VERSION) PKG_ARCH=$(GOARCH) GOARCH= MAINTAINER="$(MAINTAINER)" \
			go tool nfpm package -f packaging/nfpm.yaml -p $$fmt -t dist/ || exit 1; \
	done

clean:
	rm -rf dist
	find internal/webui/dist -mindepth 1 ! -name README.txt -delete
