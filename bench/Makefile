.PHONY: setup build-sing build-origin build-rust run smoke clean clean-results clean-all

BENCH_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(BENCH_DIR)/..)
BIN := $(BENCH_DIR)/.work/bin

setup:
	$(BENCH_DIR)/scripts/setup.sh

build-sing:
	cd $(REPO_ROOT) && go build -trimpath -ldflags='-w -s' -tags with_quic \
		-o $(BIN)/sing-trusttunnel ./cmd/sing-trusttunnel

build-origin:
	cd $(REPO_ROOT) && go build -trimpath -ldflags='-w -s' \
		-o $(BIN)/bench-origin ./bench/origin

build-rust:
	SKIP_CLIENT=1 $(BENCH_DIR)/scripts/setup.sh

run:
	$(BENCH_DIR)/scripts/run-matrix.sh

# Tiny matrix, including rust client when available, for fast tunnel verification.
smoke:
	BENCH_SIZE=67108864 BENCH_REPS=1 MATRIX_SERVERS=sing MATRIX_CLIENTS="sing rust" \
	MATRIX_TRANSPORTS=h2 MATRIX_DIRECTIONS=dl MATRIX_JOBS=1 RESULTS_DIR=$(BENCH_DIR)/results/smoke \
	$(BENCH_DIR)/scripts/run-matrix.sh

clean-results:
	rm -rf $(BENCH_DIR)/results

clean:
	rm -rf $(BENCH_DIR)/.work

clean-all: clean clean-results
	rm -f $(BENCH_DIR)/certs/cert.pem $(BENCH_DIR)/certs/key.pem
