.PHONY: all build test bench params package clean
all: bench
build:
	./run_all.sh --mode build
test:
	./run_all.sh --mode test
bench:
	./run_all.sh
params:
	python3 params/verify.py
package:
	python3 scripts/package.py
clean:
	$(MAKE) -C latpre clean
	$(MAKE) -C hybrid-mail clean
