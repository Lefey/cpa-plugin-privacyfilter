PLUGIN_NAME ?= privacyfilter
VERSION ?= 0.4.0
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
BUILD_ROOT ?= dist/staging
BUILD_DIR ?= $(BUILD_ROOT)/$(GOOS)-$(GOARCH)
REVISION ?= $(shell git rev-parse --verify HEAD)
GOFLAGS ?= -mod=readonly
GO_LDFLAGS ?= -s -w -X main.pluginVersion=$(VERSION) -X main.pluginRevision=$(REVISION)

EXT_linux = so
EXT_darwin = dylib
EXT_windows = dll
PLUGIN_EXT = $(or $(EXT_$(GOOS)),so)
PLUGIN_OUTPUT ?= $(BUILD_DIR)/$(PLUGIN_NAME).$(PLUGIN_EXT)
PLUGIN_HEADER = $(basename $(PLUGIN_OUTPUT)).h

.PHONY: build clean update-rules verify-rules

build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) GOFLAGS="$(GOFLAGS)" \
		go build -trimpath -buildvcs=true -buildmode=c-shared \
		-ldflags "$(GO_LDFLAGS)" -o $(PLUGIN_OUTPUT) .
	rm -f $(PLUGIN_HEADER)

clean:
	rm -f $(PLUGIN_OUTPUT) $(PLUGIN_HEADER)

update-rules:
	./scripts/update-rules.sh

verify-rules:
	./scripts/update-rules.sh --check
