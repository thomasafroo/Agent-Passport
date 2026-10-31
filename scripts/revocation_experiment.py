"""Simulated experiment: revocation and shared budgets behind a remote, caching enforcement point.

The shipped gateway has no cache: every reservation and dispatch reads revocation state in the
same database transaction. This script does not change that. It models a hypothetical edge
enforcement point that is separated from the authority by a network that can partition, so the
cost of caching can be measured before anyone builds it.

Everything here is a deterministic discrete-time simulation: one request per branch per second,
a simulated clock, and a simulated authority. No real gateway, network, or agent is involved.

Policies:
  online             No cache. Every request asks the authority. Unavailable while partitioned.
  cache_fail_open    Revocation view refreshed every `refresh` seconds while reachable, used
                     indefinitely while partitioned. Budget is counted locally while partitioned
                     and reported on heal.
  bounded_staleness  Same refresh, but the view is refused once older than `max_stale` seconds by
                     the edge's own clock. Budget while partitioned comes only from a lease of
                     units that the authority deducted from the shared pool in advance.

    python scripts/revocation_experiment.py
"""
from dataclasses import dataclass, asdict
import json
from pathlib import Path
import sys


@dataclass(frozen=True)
class Scenario:
    name: str = "partition"
    duration: int = 120           # seconds simulated; each branch sends one request per second
    revoke_at: int = 32           # authority revokes the compromised branch at this time (off the refresh grid)
    partition: tuple = (20, 80)   # [start, end) during which the edge cannot reach the authority
    budget: int = 300             # shared pool for both branches
    refresh: int = 5              # seconds between revocation-view refreshes while reachable
    max_stale: int = 30           # bounded_staleness: refuse a view older than this, by edge clock
    lease_units: int = 100        # bounded_staleness: units the edge leases from the pool at a time
    edge_clock_rate: float = 1.0  # edge seconds per real second; below 1.0 the edge clock runs slow


class Authority:
    """The single source of truth for revocation and the shared pool."""

    def __init__(self, budget, revoke_at):
        self.budget, self.revoke_at = budget, revoke_at
        self.spent = 0       # units consumed by admitted operations, as reported to the authority
        self.leased = 0      # units held by an outstanding lease; unavailable to anyone else

    def revoked(self, t):
        return t >= self.revoke_at

    def available(self):
        return self.budget - self.spent - self.leased

    def reserve(self):
        if self.available() < 1:
            return False
        self.spent += 1
        return True

    def lease(self, units):
        granted = max(0, min(units, self.available()))
        self.leased += granted
        return granted

    def settle_lease(self, granted, used):
        # Units stay held until the edge reports. Expiry alone never returns them.
        self.leased -= granted
        self.spent += used

    def report(self, used):
        # cache_fail_open: units admitted while partitioned are only reported on heal.
        self.spent += used


def simulate(policy, scenario):
    s = scenario
    authority = Authority(s.budget, s.revoke_at)
    p0, p1 = s.partition
    view = None                  # (revoked?, edge-clock time fetched, real time fetched)
    lease_granted = lease_left = 0
    unreported = 0
    was_reachable = True
    stats = {"revoked_admitted": 0, "last_revoked_admit": None, "healthy_admitted": 0, "healthy_denied": 0,
             "denied_reasons": {}}

    def deny(branch, reason):
        if branch == "healthy":
            stats["healthy_denied"] += 1
        stats["denied_reasons"][reason] = stats["denied_reasons"].get(reason, 0) + 1

    def admit(branch, t):
        if branch == "healthy":
            stats["healthy_admitted"] += 1
        elif authority.revoked(t):
            stats["revoked_admitted"] += 1
            stats["last_revoked_admit"] = t

    for t in range(s.duration):
        reachable = not (p0 <= t < p1)
        edge_now = t * s.edge_clock_rate
        if reachable and not was_reachable and policy == "cache_fail_open":
            # Heal: report what was admitted while partitioned, possibly beyond the budget.
            authority.report(unreported); unreported = 0
        if reachable and (view is None or t - view[2] >= s.refresh):
            view = (authority.revoked(t), edge_now, t)
        was_reachable = reachable

        for branch in ("compromised", "healthy"):
            if policy == "online":
                if not reachable:
                    deny(branch, "unavailable")
                elif branch == "compromised" and authority.revoked(t):
                    deny(branch, "revoked")
                elif authority.reserve():
                    admit(branch, t)
                else:
                    deny(branch, "budget")
                continue
            assert view is not None  # fetched at t=0, when the edge is always reachable
            if policy == "bounded_staleness" and edge_now - view[1] > s.max_stale:
                deny(branch, "view_too_stale")
                continue
            if branch == "compromised" and view[0]:
                deny(branch, "revoked")
                continue
            if policy == "cache_fail_open":
                if reachable:
                    admit(branch, t) if authority.reserve() else deny(branch, "budget")
                else:
                    unreported += 1  # optimistic: admitted with no budget check at all
                    admit(branch, t)
                continue
            # bounded_staleness spends only leased units, refilling while the authority is reachable.
            if lease_left == 0 and reachable:
                authority.settle_lease(lease_granted, lease_granted)
                lease_granted = lease_left = authority.lease(s.lease_units)
            if lease_left > 0:
                lease_left -= 1
                admit(branch, t)
            else:
                deny(branch, "budget" if reachable else "lease_exhausted")

    if policy == "cache_fail_open":
        authority.report(unreported)
    if policy == "bounded_staleness":
        authority.settle_lease(lease_granted, lease_granted - lease_left)
    lag = None if stats["last_revoked_admit"] is None else stats["last_revoked_admit"] - s.revoke_at + 1
    return {"policy": policy, "scenario": asdict(s), "revoked_admitted": stats["revoked_admitted"],
            "revocation_lag_seconds": lag, "healthy_admitted": stats["healthy_admitted"],
            "healthy_denied": stats["healthy_denied"], "spent": authority.spent, "budget": s.budget,
            "overspend": max(0, authority.spent - s.budget), "denied_reasons": stats["denied_reasons"]}


SCENARIOS = [
    Scenario(name="connected", partition=(0, 0)),
    Scenario(name="partition"),
    Scenario(name="partition, tight budget", budget=60),
    Scenario(name="partition, small lease", lease_units=50),
    Scenario(name="partition, edge clock 20% slow", edge_clock_rate=0.8, lease_units=200),
]
POLICIES = ["online", "cache_fail_open", "bounded_staleness"]


def run():
    return [simulate(policy, scenario) for scenario in SCENARIOS for policy in POLICIES]


def table(results):
    lines = ["| Scenario | Policy | Revoked ops admitted | Revocation lag (s) | Healthy denied | Spent / budget | Overspend |",
             "|---|---|---:|---:|---:|---:|---:|"]
    for r in results:
        lines.append(f"| {r['scenario']['name']} | {r['policy']} | {r['revoked_admitted']} | {r['revocation_lag_seconds'] or 0} | "
                     f"{r['healthy_denied']} | {r['spent']} / {r['budget']} | {r['overspend']} |")
    return "\n".join(lines)


def main():
    results = run()
    destination = Path("artifacts/revocation-experiment.json"); destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps({"simulation": True, "results": results}, indent=2) + "\n")
    print(table(results))
    print(f"\nSimulated, deterministic. Written to {destination}")


if __name__ == "__main__":
    sys.exit(main())
