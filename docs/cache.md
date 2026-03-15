# Parser Cache (SQLite)

PyAegis stores parsed CFG caches for faster rescans. The cache is now SQLite-based
by default for durability and resilience to partial writes.

## Default location
- `.pyaegis_cache.sqlite` (created next to the scanned root)

## Legacy pickle cache
If you need the previous pickle format, either:
- pass a cache path ending in `.pkl` when calling `ParallelProjectParser.parse_all`, or
- set `PYAEGIS_CACHE_BACKEND=pickle` in your environment.

## Notes
- The cache is best-effort. Corruption is ignored and a fresh cache is built.
- The cache is ignored by git (see `.gitignore`).
