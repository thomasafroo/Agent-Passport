# Measured results

Recorded October 30, 2026, on this development machine after a clean virtual-environment installation. These are local observations, not latency guarantees or a distributed-system benchmark.

## Correctness experiment

| Experiment | Budget | Attempts | Completed/spent | Budget denials |
|---|---:|---:|---:|---:|
| Protected shared pool, 32 worker threads | 10 | 100 agents | 10 | 90 |
| Deliberately unsafe check-then-act model | 10 | 32 workers | 32 | 0 |
| Browser story, then fork | 24 total; 3 already spent | 32 forked workers | 21 additional; 24 total | 11 |

The unsafe model uses a barrier to force every worker to observe available budget before any worker increments spend. It is an executable counterexample, not a performance comparison with the transactional implementation.

## Local latency

Environment: Python 3.13.3, Windows 11 build 26200, SQLite WAL on local disk with default synchronous settings. Each measured call opens a database connection and includes its transaction and audit write.

| Measurement | Samples | Median | p95 | Maximum |
|---|---:|---:|---:|---:|
| Authorization + reservation | 200 | 3.834 ms | 4.764 ms | 6.759 ms |
| Revoke call through observed denial | 30 | 6.911 ms | 7.298 ms | 7.507 ms |

The 100-agent protected experiment took 1,986.91 ms overall. This includes contention and service-fixture execution. The sequential authorization measurement is not a signature-only microbenchmark. The revocation measurement starts before the revoke call and ends after a subsequent request is denied; it includes both transactions. There is no cache propagation delay in this architecture.

## Verification

- **52 automated tests passed** in the fresh environment. One upstream Starlette test-client deprecation warning is present; no test failed.
- The offline verifier accepted a scenario export containing **103 events and 24 signed receipts**.
- Browser checks exercised the complete incident, concurrent fork test, graph selection, manual branch revocation, and desktop/mobile layouts. At the narrow breakpoint the graph and page had no horizontal overflow.
- A concurrent first-start check exposed a SQLite journal-mode race. Startup now retries the journal-mode transition within a bounded interval; a 12-instance regression test passes.
- Browser export verification exposed a Windows text-encoding issue. The verifier now reads UTF-8 explicitly, export preserves the server's bytes, and a non-ASCII export regression test passes.
- A live 1Password account lookup has **not** been performed. Mocked CLI behavior and secret-safe failure paths are tested.
- GitHub's Windows/Linux matrix is configured but has not run remotely.

Reproduce with:

```text
python -m pytest -q
python scripts/benchmark.py
python scripts/run_scenario.py
```

`requirements.lock` captures the dependency versions used in the clean installation. To reproduce that dependency set, install with `python -m pip install -r requirements.lock -e ".[dev]"`. The latest benchmark output is written to `artifacts/benchmark.json`; [the recorded sample](benchmark-sample.json) preserves the measurements above. New hardware or dependency versions will change timing.
