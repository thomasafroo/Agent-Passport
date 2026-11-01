"""Hypothesis profiles. Select one with HYPOTHESIS_PROFILE=dev|ci|fuzz (default: dev)."""
import os

from hypothesis import HealthCheck, settings

# SQLite commits on a laptop disk vary by tens of milliseconds, so no per-example deadline.
settings.register_profile("dev", max_examples=60, deadline=None)
# CI: no example database to persist, print a reproduction blob for any failure.
settings.register_profile("ci", max_examples=60, deadline=None, database=None, print_blob=True)
# Local soak run. Not part of the default suite.
settings.register_profile("fuzz", max_examples=3000, deadline=None, print_blob=True,
                          suppress_health_check=[HealthCheck.too_slow])
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))
