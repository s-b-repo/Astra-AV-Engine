# CAU EDR — build, test and evaluation targets.
#
# Requirements: Go 1.24+, libyara 4.3+ with headers (apt install libyara-dev),
# pkg-config. For a user-local toolchain, `source scripts/dev-env.sh` first.

BINARY   ?= cau
PKG      := ./...
GOFLAGS  ?=
VERSION  ?= $(shell command git describe --tags --always --dirty 2>/dev/null || git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -X main.version=$(VERSION)

CORPUS   ?= corpus/smoke/manifest.json
CORPUS_DB ?= corpus/smoke/hashes.txt
RULES    ?= rules
BASELINE ?= baselines/smoke.json
POLICY   ?= baselines/policy.json
EVAL_OUT ?= eval-out

export CGO_ENABLED=1

.PHONY: all build test test-race vet fmt fmt-check lint bench clean install \
        eval eval-validate eval-run eval-gate baseline ci

all: build

build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) .

test:
	go test $(GOFLAGS) $(PKG)

test-race:
	go test $(GOFLAGS) -race -count=1 $(PKG)

vet:
	go vet $(PKG)

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

fmt-check:
	@out=$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*')); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint: fmt-check vet

bench:
	go test -run '^$$' -bench . -benchmem ./scanner/ ./scanner/static/ ./scanner/stego/

# ── Evaluation harness ──────────────────────────────────────────────────────

eval-validate: build
	./$(BINARY) eval validate --corpus $(CORPUS) --verify-hashes

eval-run: build
	@mkdir -p $(EVAL_OUT)
	./$(BINARY) eval run --corpus $(CORPUS) --db $(CORPUS_DB) --rules $(RULES) \
		--out $(EVAL_OUT)/report.json

# Fail if the current tree regresses against the committed baseline.
eval-gate: eval-run
	./$(BINARY) eval gate --baseline $(BASELINE) --candidate $(EVAL_OUT)/report.json --policy $(POLICY)

eval: eval-validate eval-gate

# Re-record the baseline (review the diff before committing it).
baseline: build
	./$(BINARY) eval run --corpus $(CORPUS) --db $(CORPUS_DB) --rules $(RULES) \
		--out $(BASELINE) --quiet

ci: lint build test-race eval

# ── Install ─────────────────────────────────────────────────────────────────
# Installs the binary plus its content to PREFIX. The binary finds
# $(PREFIX)/share/cau automatically (see resources.go).
PREFIX ?= /usr/local
install: build
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/cau/rules $(DESTDIR)$(PREFIX)/share/cau/signatures
	install -m 0755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	install -m 0644 rules/*.yar $(DESTDIR)$(PREFIX)/share/cau/rules/
	install -m 0644 signatures/hashes.txt signatures/fuzzy.txt $(DESTDIR)$(PREFIX)/share/cau/signatures/

clean:
	rm -rf $(BINARY) $(BINARY).exe $(EVAL_OUT) coverage.out
