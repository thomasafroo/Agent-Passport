"""Fuzz the evidence verifier and the token/proof parsers. Local tool, not part of CI.

    python scripts/fuzz.py all --examples 20000
    python scripts/fuzz.py verify --atheris -- -max_total_time=600   # coverage-guided, if atheris is installed

Each target is a Hypothesis test, so it runs anywhere Hypothesis does and shrinks any failure to a
minimal input. With --atheris, libFuzzer drives the same target through fuzz_one_input. A clean run
means no failure was found in the inputs tried, nothing more.
"""
import argparse
import copy
from pathlib import Path
import sys
import tempfile

from hypothesis import HealthCheck, given, seed, settings, strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_passport.broker import Executor
from agent_passport.core import Denied, Holder, Passport, b64, canonical
from scripts.verify_evidence import MALFORMED, verify

json_scalar = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(), st.text(max_size=30))
json_value = st.recursive(json_scalar, lambda inner: st.one_of(st.lists(inner, max_size=4),
                                                               st.dictionaries(st.text(max_size=8), inner, max_size=4)),
                          max_leaves=20)


def mutate(document, draw):
    """Apply a few random edits anywhere in a JSON document: replace, delete, insert or duplicate."""
    document = copy.deepcopy(document)
    for _ in range(draw(st.integers(1, 3))):
        node, parents = document, []
        while isinstance(node, (dict, list)) and node and draw(st.booleans()):
            key = draw(st.sampled_from(sorted(node, key=repr) if isinstance(node, dict) else range(len(node))))
            parents.append((node, key))
            node = node[key]
        if not parents:
            continue
        parent, key = parents[-1]
        action = draw(st.sampled_from(["replace", "delete", "insert", "duplicate"]))
        if action == "replace":
            parent[key] = draw(json_value)
        elif action == "delete":
            del parent[key]
        elif action == "insert" and isinstance(parent, dict):
            parent[draw(st.text(max_size=8))] = draw(json_value)
        elif isinstance(parent, list):
            parent.insert(key, copy.deepcopy(parent[key]))
    return document


def build_fixture(directory):
    engine = Passport(directory)
    root = engine.create_run()
    Executor(engine).execute(root["token"], "staging/checkout", "logs.read", "fuzz")
    holder = Holder()
    bound = engine.create_run(holder_key=holder.public_key)
    return engine, root, bound, holder


def targets(engine, root, bound, holder):
    evidence = engine.evidence(root["run_id"])
    checkpoint = engine.checkpoint(root["run_id"])
    signed = {canonical(r) for r in evidence["receipts"] + evidence["reconciliations"]}

    @given(st.data())
    def fuzz_verify(data):
        draw = data.draw
        if draw(st.booleans()):
            document, checkpoints = draw(json_value), draw(st.lists(json_value, max_size=2))
        else:
            document, checkpoints = mutate(evidence, draw), [mutate(checkpoint, draw)] if draw(st.booleans()) else []
        try:
            result = verify(document, engine.public_key, checkpoints)
        except MALFORMED:
            return
        # Soundness: a document that verifies carries no signed statement the issuer did not make.
        for receipt in [*document["receipts"], *document.get("reconciliations", [])]:
            assert canonical(receipt) in signed or canonical({k: receipt[k] for k in ("body", "signature")}) in signed
        assert result["valid"]

    def mutated_token(draw, token):
        index = draw(st.integers(0, 4095)) % len(token)
        return token[:index] + draw(st.text(max_size=3)) + token[index + draw(st.integers(0, 3)):]

    @given(st.data())
    def fuzz_token(data):
        if data.draw(st.booleans()):
            token = mutated_token(data.draw, root["token"])
        else:
            token = data.draw(st.one_of(st.text(max_size=400), st.binary(max_size=200), json_scalar))
        if token == root["token"]:
            return
        try:
            result = engine.inspect(token)
        except Denied as error:
            assert error.rule == "IDENTITY_INVALID", error.rule
            return
        # Only a respelling of the same signed bytes can authenticate (see the xfail in test_properties).
        assert result["grant"]["id"] == root["grant"]["id"]

    @given(st.data())
    def fuzz_proof(data):
        draw = data.draw
        if draw(st.booleans()):
            proof = draw(st.one_of(st.text(max_size=400), st.binary(max_size=100), json_scalar))
        else:
            # A compromised holder can sign any body it likes.
            payload = canonical(draw(st.one_of(json_value, st.fixed_dictionaries(
                {k: json_value for k in ("ath", "op", "req", "iat", "jti")}))))
            proof = b64(payload) + "." + b64(holder.key.sign(payload))
        try:
            engine.inspect(bound["token"], proof)
        except Denied as error:
            assert error.rule in {"PROOF_INVALID", "PROOF_STALE"} or (proof is None and error.rule == "PROOF_REQUIRED"), error.rule
            return
        raise AssertionError("an unsigned or malformed proof authorized a request")

    return {"verify": fuzz_verify, "token": fuzz_token, "proof": fuzz_proof}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", choices=["verify", "token", "proof", "all"])
    parser.add_argument("--examples", type=int, default=5000)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--atheris", action="store_true", help="drive one target with atheris/libFuzzer")
    parser.add_argument("fuzzer_args", nargs="*", help="arguments passed to libFuzzer after --")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="passport-fuzz-", ignore_cleanup_errors=True) as directory:
        available = targets(*build_fixture(directory))
        if args.atheris:
            import atheris  # optional; not installed by the dev extra
            if args.target == "all":
                parser.error("--atheris drives one target at a time")
            atheris.Setup([sys.argv[0], *args.fuzzer_args], available[args.target].hypothesis.fuzz_one_input)
            atheris.Fuzz()
            return
        chosen = available if args.target == "all" else {args.target: available[args.target]}
        for name, target in chosen.items():
            configured = settings(max_examples=args.examples, deadline=None, database=None, print_blob=True,
                                  suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])(target)
            if args.seed is not None:
                configured = seed(args.seed)(configured)
            print(f"fuzz {name}: {args.examples} examples", flush=True)
            configured()
            print(f"fuzz {name}: no failure found", flush=True)


if __name__ == "__main__":
    main()
