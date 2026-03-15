# Performance & Benchmarks

PyAegis is designed to be fast enough for CI/CD gates — even on large Python repositories. This page documents benchmark results and provides tuning advice.

---

## How PyAegis Achieves Speed

1. **Multiprocessing AST parsing** — files are parsed in a `ProcessPoolExecutor` pool, saturating available CPU cores.
2. **Per-function scope** — taint analysis runs function-by-function; there is no whole-program fixed-point iteration.
3. **fnmatch pattern caching** — source/sink glob patterns are evaluated once per name lookup.
4. **Inter-procedural cache** — function return-taint results are memoized per `(fn_name, tainted_params)` key to avoid redundant analysis.
5. **No external runtime** — PyAegis has zero heavy dependencies (no JVM, no native binary, no network calls during scan).

---

## Benchmark Results

Benchmarks run on an Intel Core i7-12700 (12 cores), 32 GB RAM, SSD, Python 3.11, Ubuntu 22.04.

### Small project (< 100 files)

| Project | Files | Lines of Code | Findings | Time |
|---------|-------|--------------|----------|------|
| Flask toy app