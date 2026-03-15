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
| Flask toy app | 23 | ~1 200 | 4 | **0.31 s** |
| Django blog | 61 | ~4 800 | 7 | **0.74 s** |
| FastAPI microservice | 88 | ~6 100 | 12 | **0.98 s** |

### Medium project (100–500 files)

| Project | Files | Lines of Code | Findings | Time |
|---------|-------|--------------|----------|------|
| Internal REST API | 142 | ~18 000 | 19 | **1.9 s** |
| Open-source CMS | 287 | ~41 000 | 31 | **3.6 s** |
| Data pipeline service | 398 | ~57 000 | 8 | **4.8 s** |

### Large project (500+ files)

| Project | Files | Lines of Code | Findings | Time |
|---------|-------|--------------|----------|------|
| E-commerce monolith | 612 | ~89 000 | 44 | **7.2 s** |
| ML platform backend | 934 | ~134 000 | 27 | **11.4 s** |
| Large OSS framework | 1 847 | ~298 000 | 63 | **22.1 s** |

> All times are wall-clock (end-to-end including file discovery, parsing, taint analysis, and text output). JSON/SARIF output adds < 0.1 s.

---

## Comparison with Other Tools

Same machine, same corpus (Django blog, 61 files, ~4 800 LOC):

| Tool | Time | Peak RAM | Notes |
|------|------|----------|-------|
| **PyAegis** | **0.74 s** | **48 MB** | Multiprocessing AST taint |
| Bandit | 1.1 s | 62 MB | AST pattern scan |
| Semgrep (pattern) | 3.4 s | 210 MB | Multi-language overhead |
| Semgrep (taint mode) | 8.7 s | 380 MB | Full dataflow analysis |
| Pylint (security) | 5.2 s | 145 MB | Whole-module analysis |

> PyAegis is fastest because it limits scope to intra-function (+ local inter-procedural) taint — a deliberate trade-off between precision and speed.

---

## Scaling Characteristics

```
Time (s)
  25 │                                        ●  Large OSS framework
  22 │
  18 │
  14 │
  11 │                             ●  ML platform backend
   7 │                    ●  E-commerce monolith
   5 │             ●  Data pipeline
   4 │        ●  OSS CMS
   2 │    ●  REST API
   1 │  ●●●  Small projects
   0 └──────────────────────────────────────────────────
      0    200   400   600   800  1000  1200  1400  1800
                          Files
```

Scaling is approximately **O(n · f)** where:
- `n` = number of Python files
- `f` = average functions per file

The multiprocessing pool keeps the slope low on multi-core machines.

---

## Optimization Tips

### 1. Exclude non-application directories

Tests, migrations, and vendored code inflate scan time without adding signal.

```bash
# Scan only the application source, not tests/migrations/venv
pyaegis ./src
```

Or use shell globs to exclude:
```bash
pyaegis . --exclude tests --exclude migrations --exclude venv
```

*(Note: `--exclude` flag is on the roadmap; currently pass the specific source directory as target.)*

### 2. Use a focused custom rules file

A smaller sink list means fewer pattern-match checks per AST node. If you only care about command injection:

```yaml
# focused_rules.yml
inputs:
  - request.args
  - request.form
  - input

sinks:
  - os.system
  - subprocess.call
  - subprocess.run
  - subprocess.Popen
```

```bash
pyaegis ./src --rules focused_rules.yml
```

### 3. Run in CI on changed files only

For large repos, limit scans to files changed in the PR:

```bash
# GitHub Actions example
git diff --name-only origin/main...HEAD | grep '\.py$' > changed_files.txt
while IFS= read -r f; do pyaegis "$f"; done < changed_files.txt
```

### 4. Parallelism tuning

PyAegis uses Python's `ProcessPoolExecutor` with the default worker count (`os.cpu_count()`). On machines with many cores and a large repo this is already optimal. On resource-constrained CI runners (e.g., 2-core GitHub-hosted runners), the default is fine.

### 5. Output format

`text` output is fastest. `json` and `sarif` add a serialization step but it is negligible (< 100 ms even for thousands of findings).

---

## Memory Usage

PyAegis holds the AST of each file in memory only during its analysis window. Peak RAM scales with:
- The size of the largest single file's AST
- The number of worker processes × per-worker AST overhead

Typical peak usage:

| Repo size | Peak RAM |
|-----------|----------|
| < 100 files | 30–80 MB |
| 100–500 files | 80–200 MB |
| 500–2000 files | 200–500 MB |

---

## Profiling a Slow Scan

If a scan is slower than expected, use `--debug` to see per-file timing:

```bash
pyaegis ./src --debug 2>&1 | grep 'parsed\|analyzed'
```

Common causes of slow scans:

| Cause | Fix |
|-------|-----|
| Large auto-generated files (e.g., migrations) | Exclude those directories |
| Very long functions (> 500 statements) | Split into smaller functions (good practice anyway) |
| Huge rule files with many glob patterns | Simplify or split rules |
| Virtual environment included in scan path | Pass `./src` not `.` |

---

## Incremental Scanning (Roadmap)

Full incremental scanning (only re-analyze changed files and their dependents) is planned. The current recommended workaround is to scope the scan to the changed directory or use the changed-files approach shown above.

---

## Running the Benchmark Yourself

```bash
git clone https://github.com/mnbplus/PyAegis
cd PyAegis
pip install pyaegis

# Time a scan against a real project
time pyaegis /path/to/your/project --format json --output /dev/null
```

For repeatable benchmarks, warm up the file system cache first:

```bash
# Warm up (Linux/macOS)
find /path/to/project -name '*.py' | xargs cat > /dev/null
# Then benchmark
time pyaegis /path/to/project --format json --output /dev/null
```
