# FAQ

## 1) What is PyAegis?

PyAegis is a Python-focused SAST tool that performs rule-driven **source → sink** analysis and can export results as text/JSON/SARIF.

## 2) Is PyAegis a replacement for Bandit or Semgrep?

Not necessarily.

- Use **Bandit** for fast, well-known Python security lint checks.
- Use **Semgrep** for multi-language pattern scanning and large rule ecosystems.
- Use **PyAegis** when you want a small, Python-first scanner with minimal YAML rules and CI-friendly outputs.

## 3) What does “source” and “sink” mean?

- **Source**: a place where untrusted data enters your program (user input, request params, env vars).
- **Sink**: a sensitive API where untrusted data is dangerous (command execution, eval/exec, deserialization, SQL execution).

## 4) What rule format does PyAegis use?

A YAML file with:

- `inputs`: sources
- `sinks`: sinks

See: [Writing rules](rules.md)

## 5) Why does PyAegis exit with code 1?

Exit code `1` is used when findings are detected (useful as a CI gate). It may also be used for fatal scan errors.

## 6) How do I generate SARIF?

```bash
pyaegis . --format sarif --output pyaegis-results.sarif
```

## 7) GitHub Actions shows no alerts after uploading SARIF. Why?

Common causes:

- workflow lacks `permissions: security-events: write`
- SARIF file path is wrong
- repository does not have code scanning enabled (org policy)

See: [CI integration](ci-integration.md)

## 8) Does PyAegis support Django/FastAPI/Flask out of the box?

Not fully yet. You can still model many frameworks by defining `inputs` that match your code conventions (e.g., `request`). Framework-aware modeling is on the roadmap.

## 9) Why am I getting false positives?

Common reasons:

- rule set is too broad (too many sources/sinks)
- the analyzer does not model sanitizers/validators yet
- aliasing/dynamic imports prevent precise resolution

Try narrowing sinks first; then expand gradually.

## 10) Why am I missing issues (false negatives)?

PyAegis currently focuses on simple intra-procedural flows and may miss:

- taint propagated across function calls
- dynamic dispatch, reflection, complex aliasing
- flows across modules without explicit data movement in the same function

## 11) Can I ignore/baseline findings?

Not yet (planned). For now, you can:

- split rulesets to focus on high-signal sinks
- run only on changed paths in CI

## 12) What Python versions are supported?

The project targets Python **3.8+**.

---

If you hit an issue, please open a GitHub issue with a minimal repro and your rules file.
