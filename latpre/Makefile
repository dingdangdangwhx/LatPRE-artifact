CC ?= cc
AR ?= ar
BUILD ?= build
GAUSSIAN ?= openfhe
ifneq ($(GAUSSIAN),openfhe)
$(error Only the OpenFHE-style Gaussian sampler is provided)
endif
CPPFLAGS += -Iinclude -Isrc -Ithird_party/sha3 -DLBPRE_GAUSSIAN_OPENFHE -D_POSIX_C_SOURCE=200809L
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -Wshadow
LDLIBS += -lm
MPFR_CFLAGS ?= $(shell pkg-config --cflags mpfr gmp 2>/dev/null)
MPFR_LIBS ?= $(shell pkg-config --libs mpfr gmp 2>/dev/null || echo '-lmpfr -lgmp')

SOURCES = params serial registry lbpre ring sampling
OBJECTS = $(addprefix $(BUILD)/,$(addsuffix .o,$(SOURCES))) $(BUILD)/sha3_t.o $(BUILD)/keccakf1600.o
HEADERS = $(wildcard include/*.h) src/internal.h src/sampling_openfhe.inc src/extended_params.inc bench/extended_expected.inc
TESTS = test_ring test_sampling_openfhe test_sampling_cbd test_core_edges test_serial test_lbpre test_extended
TEST_BINS = $(addprefix $(BUILD)/,$(TESTS))

.PHONY: all test bench sanitize clean
all: $(BUILD)/liblbpre.a $(BUILD)/bench_lbpre

$(BUILD):
	mkdir -p $@

$(BUILD)/%.o: src/%.c $(HEADERS) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/sha3_t.o: third_party/sha3/sha3_t.c third_party/sha3/sha3_t.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/keccakf1600.o: third_party/sha3/keccakf1600.c third_party/sha3/keccakf1600.h third_party/sha3/plat_local.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/liblbpre.a: $(OBJECTS)
	$(AR) rcs $@ $^

$(BUILD)/bench_lbpre: bench/bench_lbpre.c $(BUILD)/liblbpre.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(BUILD)/liblbpre.a $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD)/test_%: tests/test_%.c $(BUILD)/liblbpre.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(BUILD)/liblbpre.a $(LDFLAGS) $(LDLIBS) -o $@

# MPFR/GMP validate frozen decimal constants only; they are not runtime samplers.
$(BUILD)/test_lbpre: tests/test_lbpre.c $(BUILD)/liblbpre.a
	$(CC) $(CPPFLAGS) $(MPFR_CFLAGS) $(CFLAGS) $< $(BUILD)/liblbpre.a $(LDFLAGS) $(LDLIBS) $(MPFR_LIBS) -o $@

test: $(TEST_BINS)
	@set -e; for test in $(TEST_BINS); do ./$$test; done

bench: $(BUILD)/bench_lbpre
	$(BUILD)/bench_lbpre --samples 1000 --warmup 10

sanitize:
	$(MAKE) BUILD=build-sanitize CFLAGS='-O1 -g -std=c11 -Wall -Wextra -Wshadow -fno-omit-frame-pointer -fsanitize=address,undefined' LDFLAGS='-fsanitize=address,undefined' test

clean:
	rm -rf build build-sanitize
