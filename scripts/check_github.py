"""Opt-in live check of the GitHub upstream. Files two real issues; prints no token or upstream text.

Needs PASSPORT_GITHUB_REPO, PASSPORT_OP_REFERENCES (with a GitHub token for repo/checkout
patch.propose) and the 1Password backend configuration. See docs/github-upstream.md.

Three operations, one shared budget of three units:

  completed     an ordinary dispatch files an issue; the unit is spent
  lost answer   the issue is filed but this script discards GitHub's answer and records the
                outcome as unknown; an effect lookup finds the issue and settles it as completed.
                Until GitHub's list catches up, the lookup is inconclusive and changes nothing,
                so it is repeated a few times.
  lost request  this script records an unknown outcome without sending anything; the lookup
                finds nothing, cannot fence the ID, and leaves the unit reserved; the operator
                then decides by hand, with that basis

Evidence for offline verification is written to artifacts/github-check-evidence.json, with the
issuer public key beside it.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent_passport.core import Denied, verify_receipt
from agent_passport.broker import Executor, backend_from_environment, passport_from_environment
from agent_passport.github import PAIR, GitHubIssues

# GitHub's issue list is eventually consistent: a just-created issue can be missing for a moment.
# An inconclusive lookup changes nothing, so the operator may simply ask again.
LOOKUP_ATTEMPTS, LOOKUP_WAIT = 6, 5.0


def unknown_after(executor, root, key, send):
    """Reserve and dispatch, optionally send to GitHub, then settle as if the answer was lost."""
    op = executor.passport.reserve(root["token"], *PAIR, key)
    assert executor.passport.dispatch(op["id"])
    if send:
        credential = executor.provider.resolve(*PAIR)
        try:
            executor.service.execute(credential, *PAIR, op["id"])
        finally:
            credential = None
    executor.passport.settle(op["id"], "unknown", {"error": "Answer discarded by the live check to model a lost response."})
    return op["id"]


def main():
    if not os.environ.get("PASSPORT_GITHUB_REPO") or not os.environ.get("PASSPORT_OP_REFERENCES"):
        print("Set PASSPORT_GITHUB_REPO and PASSPORT_OP_REFERENCES first. See docs/github-upstream.md.")
        return 2
    artifacts = ROOT / "artifacts"
    artifacts.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        try:
            backend = backend_from_environment()
            passport = passport_from_environment(directory, backend)
            executor = Executor.from_environment(passport, backend)
        except ValueError as error:
            print(f"Invalid configuration: {error} See docs/github-upstream.md.")
            return 2
        assert isinstance(executor.service, GitHubIssues)
        root = passport.create_run(budget=3)
        lines, ok = [f"Provider: {executor.provider.mode}; upstream: {executor.upstream}"], True

        first = executor.execute(root["token"], *PAIR, "live-completed")
        valid = verify_receipt(first["receipt"], passport.public_key)
        url = (first["result"] or {}).get("url", "-") if first["state"] == "completed" else "-"
        lines.append(f"1 completed:    {first['state']}; receipt valid: {valid}; issue: {url}")
        ok &= first["state"] == "completed" and valid

        lost = unknown_after(executor, root, "live-lost-answer", send=True)
        misses, outcome = 0, None
        for attempt in range(LOOKUP_ATTEMPTS):
            try:
                outcome = executor.resolve(lost)["state"]
                break
            except Denied as error:
                outcome = error.rule
                if error.rule != "LOOKUP_INCONCLUSIVE":
                    break
                misses += 1
                held = (passport.operation(lost) or {}).get("state")
                ok &= held == "unknown"  # an absent issue never settles anything
                if attempt + 1 < LOOKUP_ATTEMPTS:
                    time.sleep(LOOKUP_WAIT)
        lines.append(f"2 lost answer:  lookup -> {outcome}; inconclusive first: {misses} time(s), unit kept each time")
        ok &= outcome == "reconciled_completed"

        never = unknown_after(executor, root, "live-lost-request", send=False)
        before = passport.snapshot(root["run_id"])["run"]["reserved"]
        try:
            executor.resolve(never)
            lines.append("3 lost request: lookup settled an unfenced absence (unexpected)")
            ok = False
        except Denied as error:
            after, state = passport.snapshot(root["run_id"])["run"]["reserved"], (passport.operation(never) or {}).get("state")
            lines.append(f"3 lost request: lookup -> {error.rule}; operation still {state}, reserved units {before} -> {after}")
            ok &= error.rule == "LOOKUP_INCONCLUSIVE" and state == "unknown" and after == before
        decided = passport.reconcile(never, "not_executed", "The live check settled this as unknown without sending any request to GitHub.",
                                     "Live check operator")
        lines.append(f"  operator:     {decided['state']}")

        run = passport.snapshot(root["run_id"])["run"]
        lines.append(f"Budget: spent {run['spent']}, reserved {run['reserved']} of {run['budget']}")
        ok &= (run["spent"], run["reserved"]) == (2, 0)
        evidence = passport.evidence(root["run_id"])
        (artifacts / "github-check-evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        (artifacts / "github-check-public-key.txt").write_text(passport.public_key + "\n", encoding="utf-8")
        lines.append("Evidence: artifacts/github-check-evidence.json (key: artifacts/github-check-public-key.txt)")
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
