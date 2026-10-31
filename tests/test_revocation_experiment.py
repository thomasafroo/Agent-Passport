"""Properties of the simulated stale-cache and partition experiment (not the shipped gateway)."""
import itertools

from scripts.revocation_experiment import SCENARIOS, Scenario, run, simulate


def by(results, scenario, policy):
    return next(r for r in results if r["scenario"]["name"] == scenario and r["policy"] == policy)


def grid():
    for budget, partition, refresh, stale, lease, rate in itertools.product(
            [20, 60, 300], [(0, 0), (10, 40), (20, 80), (35, 100)], [1, 5, 15], [5, 30], [10, 100], [1.0, 0.8, 0.5]):
        yield Scenario(name="grid", budget=budget, partition=partition, refresh=refresh,
                       max_stale=stale, lease_units=lease, edge_clock_rate=rate)


def test_simulation_is_deterministic():
    assert run() == run()


def test_online_checks_never_admit_a_revoked_branch_and_pay_in_availability():
    for scenario in grid():
        assert simulate("online", scenario)["revoked_admitted"] == 0
        assert simulate("online", scenario)["overspend"] == 0
    result = simulate("online", Scenario())
    assert result["healthy_denied"] == 60 and result["denied_reasons"]["unavailable"] == 120


def test_fail_open_cache_admits_a_revoked_branch_for_the_whole_partition_and_overspends():
    results = run()
    partition = by(results, "partition", "cache_fail_open")
    assert partition["revocation_lag_seconds"] == 80 - 32  # until the partition heals
    assert by(results, "partition, tight budget", "cache_fail_open")["overspend"] > 0


def test_cache_lag_while_connected_is_bounded_by_the_refresh_interval():
    for policy in ("cache_fail_open", "bounded_staleness"):
        for refresh in (1, 5, 15):
            lag = simulate(policy, Scenario(partition=(0, 0), refresh=refresh))["revocation_lag_seconds"] or 0
            assert 0 < lag <= refresh or (lag == 0 and 32 % refresh == 0)


def test_bounded_staleness_never_overspends_and_bounds_revocation_by_edge_clock():
    for scenario in grid():
        result = simulate("bounded_staleness", scenario)
        assert result["overspend"] == 0 and result["spent"] <= scenario.budget
        bound = max(scenario.refresh, scenario.max_stale / scenario.edge_clock_rate)
        assert (result["revocation_lag_seconds"] or 0) <= bound


def test_a_slow_edge_clock_stretches_the_nominal_staleness_bound():
    results = run()
    nominal = by(results, "partition", "bounded_staleness")["revocation_lag_seconds"]
    drifted = by(results, "partition, edge clock 20% slow", "bounded_staleness")["revocation_lag_seconds"]
    assert drifted > nominal


def test_every_reported_scenario_is_listed():
    assert {s.name for s in SCENARIOS} == {r["scenario"]["name"] for r in run()}
