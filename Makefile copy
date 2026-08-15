# Top-level convenience targets. Firmware-specific targets live in firmware/Makefile.

PY      ?= python3
WORKERS ?= 4

.PHONY: help setup build check matrix heatmap clean

help:
	@echo "faultlab"
	@echo "  make setup     install python deps (needs arm-none-eabi-gcc separately)"
	@echo "  make build     build all 12 firmware binaries"
	@echo "  make check     determinism gate — run after ANY harness change"
	@echo "  make matrix    full campaign matrix -> analysis/results/*.parquet"
	@echo "  make heatmap   regenerate analysis/heatmap.html"

setup:
	$(PY) -m pip install -r requirements.txt

build:
	$(MAKE) -C firmware matrix

# The gate. Same binary, same fault set, worker counts 1/2/4/8 -> identical
# exploitable sets, or this fails. A fault harness that returns different
# answers on different runs is worse than no harness, because its output
# still looks authoritative.
check: build
	cd harness && $(PY) tests/test_determinism.py

matrix: build
	cd harness && $(PY) -m faultlab.cli matrix --workers $(WORKERS) --out ../analysis/results

heatmap: build
	$(PY) analysis/heatmap.py

clean:
	$(MAKE) -C firmware clean
	rm -rf analysis/results analysis/heatmap.html
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
