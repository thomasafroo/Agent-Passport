"""Run the entire incident and fork experiment without a browser."""
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_passport.core import Passport
from agent_passport.broker import Executor
from agent_passport.demo import Demo


def main():
    with tempfile.TemporaryDirectory() as directory:
        passport = Passport(directory)
        demo = Demo(passport, Executor(passport))
        for _ in range(4):
            state = demo.step()
            print(state["message"])
        state = demo.fork()
        print(state["message"])
        evidence = {**passport.evidence(demo.run_id), "metrics":state["metrics"], "credential_mode":"synthetic"}
        destination = Path("artifacts"); destination.mkdir(exist_ok=True)
        (destination / "scenario-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        (destination / "issuer-public-key.txt").write_text(passport.public_key + "\n")
        assert state["metrics"]["unrelated_branch_completed"]
        assert state["metrics"]["fork"]["completed"] == 21
        assert state["metrics"]["fork"]["denied"] == 11
        print("Evidence: artifacts/scenario-evidence.json")


if __name__ == "__main__": main()
