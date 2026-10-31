# Revocation behind a stale cache and a partitioned network

**This is a simulation.** The shipped gateway has no authorization cache: every reservation and dispatch reads revocation state inside the same database transaction. Nothing here changes that. The experiment models a hypothetical remote enforcement point, an "edge", to measure what caching would cost before anyone builds one.

Run it with:

```powershell
python scripts/revocation_experiment.py
```

It is deterministic. It writes `artifacts/revocation-experiment.json` and prints the table below. The properties under "What holds" are checked by `tests/test_revocation_experiment.py`, including a 1,296-scenario parameter grid.

## Setup

Two branches share one root budget. Each sends one request per second for 120 simulated seconds. The authority revokes the compromised branch at second 32. In the partition scenarios, the edge cannot reach the authority from second 20 to second 80.

| Policy | Revocation view | Budget while partitioned |
|---|---|---|
| `online` | None. Every request asks the authority, as the shipped gateway does. | No admissions. |
| `cache_fail_open` | Refreshed every 5 seconds while reachable, then used indefinitely. | Admits with no budget check and reports on heal. |
| `bounded_staleness` | Refreshed every 5 seconds, refused once more than 30 seconds old by the edge's own clock. | Spends only units leased from the pool in advance, 100 at a time unless stated. |

Leased units are deducted from the shared pool when granted and stay held until the edge reports its usage. Expiry alone never returns them, for the same reason a timeout never refunds an unknown operation.

## Results

| Scenario | Policy | Revoked ops admitted | Revocation lag (s) | Healthy denied | Spent / budget | Overspend |
|---|---|---:|---:|---:|---:|---:|
| connected | online | 0 | 0 | 0 | 152 / 300 | 0 |
| connected | cache_fail_open | 3 | 3 | 0 | 155 / 300 | 0 |
| connected | bounded_staleness | 3 | 3 | 0 | 155 / 300 | 0 |
| partition | online | 0 | 0 | 60 | 80 / 300 | 0 |
| partition | cache_fail_open | 48 | 48 | 0 | 200 / 300 | 0 |
| partition | bounded_staleness | 14 | 14 | 34 | 132 / 300 | 0 |
| partition, tight budget | online | 0 | 0 | 80 | 60 / 60 | 0 |
| partition, tight budget | cache_fail_open | 48 | 48 | 40 | 160 / 60 | 100 |
| partition, tight budget | bounded_staleness | 0 | 0 | 90 | 60 / 60 | 0 |
| partition, small lease | online | 0 | 0 | 60 | 80 / 300 | 0 |
| partition, small lease | cache_fail_open | 48 | 48 | 0 | 200 / 300 | 0 |
| partition, small lease | bounded_staleness | 0 | 0 | 55 | 90 / 300 | 0 |
| partition, edge clock 20% slow | online | 0 | 0 | 60 | 80 / 300 | 0 |
| partition, edge clock 20% slow | cache_fail_open | 48 | 48 | 0 | 200 / 300 | 0 |
| partition, edge clock 20% slow | bounded_staleness | 21 | 21 | 27 | 146 / 300 | 0 |

Revocation lag is the number of seconds after revocation during which the revoked branch was still admitted. Zero means it was never admitted after revocation.

## What holds

- **Online checks never admit a revoked branch, and never overspend.** The price is availability: during the partition, the healthy branch is denied for all 60 seconds.
- **A fail-open cache turns a partition into an unbounded revocation delay.** The revoked branch kept working until the network healed, 48 seconds here, and would keep going for as long as the partition lasts. Counting budget locally overspent a tight pool by 100 units, more than the pool itself.
- **Bounded staleness caps the revocation delay and never overspends.** Across the parameter grid, the revoked branch is admitted for at most the larger of the refresh interval and the staleness limit, divided by the edge clock rate. Leases kept spend within the budget in every case.
- **The bound is only as good as the edge's clock.** With the edge clock running 20% slow, the same 30-second limit let the revoked branch work for 21 seconds instead of 14. A real deployment needs a stated clock-drift bound, or a monotonic clock checked against the authority.
- **Lease size is a third dial.** Smaller leases strand fewer units with a partitioned edge and also end its admissions sooner. In the small-lease and tight-budget runs, the lease ran out before revocation, so no revoked operation was admitted, at the cost of more denied healthy requests.
- **Caching delays revocation even while connected.** With a 5-second refresh, the revoked branch completed 3 more operations before the next refresh saw the revocation.

## Limits

This is a model, not a measurement of a distributed system. It has one edge, fixed request rates, instant messages while connected, no message loss beyond the partition window, and a constant clock-rate error. It does not model several edges competing for leases, an authority failover, or an adversary who controls the partition. The numbers show the shape of each trade-off, not latencies or guarantees for any real deployment.
