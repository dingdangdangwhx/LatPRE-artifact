CC ?= cc
CFLAGS ?= -O3 -std=c11 -Wall -Wextra
PKG_CONFIG ?= pkg-config
SAGE ?= sage
PROFILE ?= all
ROLE ?= all
MODE ?= classical
BUILD := build
BACKENDS := backends
ROUNDING_SRC := $(BACKENDS)/cbd_rounding.c $(BACKENDS)/lbpre_dist.c $(BACKENDS)/crt_ntt.c
ROUNDING_HEADERS := $(BACKENDS)/lbpre_dist.h $(BACKENDS)/crt_ntt.h

.PHONY: all rounding correctness security check-imports clean
all: rounding
rounding: $(BUILD)/cbd_rounding

$(BUILD):
	mkdir -p $@

$(BUILD)/cbd_rounding: $(ROUNDING_SRC) $(ROUNDING_HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $(shell $(PKG_CONFIG) --cflags mpfr gmp) $(ROUNDING_SRC) -o $@ $(shell $(PKG_CONFIG) --libs mpfr gmp) -lm

correctness: rounding
	$(SAGE) -python certify.py --profile $(PROFILE) --output results/correctness-$(PROFILE).json

security:
	$(SAGE) -python security.py --profile $(PROFILE) --role $(ROLE) --mode $(MODE) --output results/security-$(MODE)-$(PROFILE)-$(ROLE).json

check-imports:
	$(SAGE) -python certify.py --check-imports
	$(SAGE) -python security.py --check-imports

clean:
	rm -rf $(BUILD)
