E2E_FLAGS ?= -v --trace

.PHONY: deps
deps:
	mkdir -p bin
	go mod download
	grep ginkgo go.mod | awk '{ print $$1 "/ginkgo@" $$2 }' | GOBIN=$$PWD/bin xargs go install

.PHONY: e2e
e2e: deps
	bin/ginkgo run $(E2E_FLAGS) ./
