E2E_FLAGS ?= -v --trace

e2e:
	ginkgo run $(E2E_FLAGS) ./
