GO ?= go
PYTHON ?= python3
SAMPLES ?= 1000
WARMUP ?= 10
OUT ?= runs/benchmark.json
export GO
export GOMAXPROCS = 1

.PHONY: build test proton-test demo bench wire-sizes clean
build:
	$(MAKE) -C ../latpre build/liblbpre.a
	@mkdir -p bin
	$(PYTHON) tools/go.py build -o bin/hybrid-mail ./cmd/hybrid-mail
	$(PYTHON) tools/go.py build -o bin/hybrid-bench ./cmd/hybrid-bench
	$(PYTHON) tools/go.py build -o bin/hybrid-wire-size ./cmd/hybrid-wire-size
test: build
	$(PYTHON) tools/go.py test -p 1 ./...
	$(PYTHON) tools/go.py vet ./...
proton-test:
	$(PYTHON) tools/go.py test -p 1 github.com/ProtonMail/go-crypto/openpgp/v2 -run '^TestForwardingFull$$' -count=1 -v
demo: build
	$(PYTHON) tools/demo.py
bench: build
	@$(PYTHON) -c 'from pathlib import Path; import sys; Path(sys.argv[1]).parent.mkdir(parents=True, exist_ok=True)' "$(OUT)"
	bin/hybrid-bench -n $(SAMPLES) -warmup $(WARMUP) -out "$(OUT)"
wire-sizes: build
	@mkdir -p runs
	bin/hybrid-wire-size -out runs/wire-sizes.json
clean:
	rm -rf bin
