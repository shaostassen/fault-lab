# Top-level convenience targets. Firmware-specific targets live in firmware/Makefile.

PY      ?= python3
WORKERS ?= 4

.PHONY: help setup build build-rv32 check check-all matrix heatmap clean

help:
	@echo "faultlab"
	@echo "  make setup     install python deps (needs arm-none-eabi-gcc separately)"
	@echo "  make build     build all 12 Cortex-M3 binaries"
	@echo "  make build-rv32 same cross product for RV32I"
	@echo "  make check     determinism gate — run after ANY harness change"
	@echo "  make check-all every gate CI runs (both ISAs + cross-backend)"
	@echo "  make matrix    full campaign matrix -> analysis/results/*.parquet"
	@echo "  make heatmap   regenerate analysis/heatmap.html"

setup:
	$(PY) -m pip install -r requirements.txt

build:
	$(MAKE) -C firmware matrix

build-rv32:
	$(MAKE) -C firmware matrix-rv32

# The gate. Same binary, same fault set, worker counts 1/2/4/8 -> identical
# exploitable sets, or this fails. A fault harness that returns different
# answers on different runs is worse than no harness, because its output
# still looks authoritative.
check: build
	cd harness && $(PY) tests/test_determinism.py

# Everything CI runs, in the same order. `check` alone covers only the
# Cortex-M3 path, which was the whole project once and is now about half of it.
check-all: build build-rv32
	cd harness && $(PY) tests/test_determinism.py
	cd harness && $(PY) tests/test_regression.py
	cd harness && $(PY) tests/test_rv32_regression.py
	cd harness && $(PY) tests/test_qemu_crossval.py

matrix: build
	cd harness && $(PY) -m faultlab.cli matrix --workers $(WORKERS) --out ../analysis/results

heatmap: build
	$(PY) analysis/heatmap.py

clean:
	$(MAKE) -C firmware clean
	rm -rf analysis/results analysis/heatmap.html
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
