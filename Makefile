# Common tasks. `make check` is what CI runs.
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)
FUZZTIME ?= 15s

# package:FuzzTarget pairs, one fuzz run each.
FUZZ_TARGETS := \
	cloudtrail:FuzzReplay \
	evidence:FuzzVerify \
	evidence:FuzzSingleByteTamper \
	host:FuzzLoadAndScan \
	host:FuzzRedactCmdline \
	detect:FuzzLoadSuppressions \
	detect:FuzzWildcardMatch \
	awswatch:FuzzFetchAndBuffer

.PHONY: build check fmt vet test fuzz clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/cad ./cmd/cad
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/cad-watch ./cmd/cad-watch

check: fmt vet test

fmt:
	@unformatted=$$(gofmt -l .); if [ -n "$$unformatted" ]; then echo "Files need gofmt:"; echo "$$unformatted"; exit 1; fi

vet:
	go vet ./...

test:
	go test -race ./...

fuzz:
	@set -e; for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; name=$${t##*:}; \
		echo "== $$pkg $$name ($(FUZZTIME))"; \
		go test ./internal/$$pkg -run '^$$' -fuzz "^$$name\$$" -fuzztime $(FUZZTIME); \
	done

clean:
	rm -rf bin dist build
