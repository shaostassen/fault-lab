"""Parquet result store.

Parquet rather than HDF5 (which ARCHIE uses) because the analysis loop is the
bottleneck on a project like this, not the write path. DuckDB queries Parquet
directly with no load step, and the same files ship straight to the web
visualisation as a filtered subset.

Partition by build so the compiler sweep is a directory listing rather than a
predicate: analysis/results/build=secureboot-hardened-O2/vector=forged/*.parquet
"""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

SCHEMA = pa.schema([
    ("build", pa.string()), ("vector", pa.string()), ("order", pa.int8()),
    ("trigger", pa.int32()), ("pc", pa.uint32()), ("model", pa.int8()),
    ("target_reg", pa.int8()), ("value", pa.int64()), ("outcome", pa.int8()),
    ("instructions", pa.int32()), ("verdict", pa.uint32()),
    ("marks", pa.uint32()), ("triggers", pa.string()),
])


def write(rows, out_dir: str | Path) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cols = {f.name: [] for f in SCHEMA}
    for r in rows:
        d = asdict(r)
        for k in cols:
            cols[k].append(d[k])
    tbl = pa.table(cols, schema=SCHEMA)
    path = out_dir / f"{rows[0].build}__{rows[0].vector}.parquet"
    pq.write_table(tbl, path, compression="zstd")
    return path


def query(pattern: str, sql: str):
    import duckdb
    return duckdb.sql(sql.replace("{t}", f"read_parquet('{pattern}')")).df()
