"""Offline integrity verification with an independently pinned issuer key."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_passport.core import canonical, verify_receipt

# Every error verify() raises on a malformed or tampered document. The CLI reports each as a failed verification.
MALFORMED = (ValueError, KeyError, TypeError, AttributeError)


def verify(evidence, pinned_key, checkpoints=()):
    """Checkpoints must come from a witness copy, never from the evidence being checked."""
    if evidence.get("public_key") != pinned_key:
        raise ValueError("Issuer does not match pinned key")
    previous, hashes = "0" * 64, []
    for event in evidence["events"]:
        body = {k:v for k,v in event.items() if k not in {"seq", "hash"}}
        if body["previous"] != previous or hashlib.sha256(canonical(body)).hexdigest() != event["hash"]:
            raise ValueError("Event chain is altered or reordered")
        previous = event["hash"]
        hashes.append(previous)
    approvals, approved = evidence.get("approvals", []), {}
    for receipt in approvals:
        body = receipt.get("body", {})
        if not verify_receipt(receipt, pinned_key) or body.get("type") != "approval" or body.get("decision") not in {"approved", "denied"}:
            raise ValueError("Invalid approval signature")
        if body["run_id"] != evidence["run"]["id"]:
            raise ValueError("Approval belongs to another run")
        if body["decision"] == "approved":
            approved[body["operation_id"]] = hashlib.sha256(canonical(body)).hexdigest()
    for receipt in evidence["receipts"]:
        # Operation receipts carry no type, so a signed reconciliation, approval or checkpoint cannot pose as one.
        if not verify_receipt(receipt, pinned_key) or "type" in receipt["body"]:
            raise ValueError("Invalid receipt signature")
        if receipt["body"]["run_id"] != evidence["run"]["id"]:
            raise ValueError("Receipt belongs to another run")
        if "approval" in receipt["body"] and approved.get(receipt["body"]["operation_id"]) != receipt["body"]["approval"]:
            raise ValueError("Receipt cites an approval missing from the evidence")
    reconciliations = evidence.get("reconciliations", [])
    for receipt in reconciliations:
        if not verify_receipt(receipt, pinned_key) or receipt["body"].get("type") != "reconciliation":
            raise ValueError("Invalid reconciliation signature")
        if receipt["body"]["run_id"] != evidence["run"]["id"]:
            raise ValueError("Reconciliation belongs to another run")
    anchored = 0
    for checkpoint in checkpoints:
        body = checkpoint.get("body", {})
        if not verify_receipt(checkpoint, pinned_key) or body.get("type") != "checkpoint":
            raise ValueError("Invalid checkpoint signature")
        if body["run_id"] != evidence["run"]["id"]:
            raise ValueError("Checkpoint belongs to another run")
        size = body["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("Checkpoint size is invalid")
        if size > len(hashes):
            raise ValueError("Evidence is missing events that a checkpoint covers")
        if (hashes[size - 1] if size else "0" * 64) != body["head"]:
            raise ValueError("Event history differs from a checkpoint")
        anchored = max(anchored, size)
    if checkpoints:
        chain = ("Checkpoints anchor the chain up to the latest one only as far as the witness copy is independent of the issuer. "
                 "Events after it are unanchored, and a checkpoint does not make the issuer's log truthful.")
    else:
        chain = "An unanchored event chain cannot prove completeness or prevent wholesale rewriting."
    return {"valid": True, "events":len(evidence["events"]), "receipts":len(evidence["receipts"]),
            "reconciliations":len(reconciliations), "approvals":len(approvals), "head":previous, "checkpoints":len(checkpoints),
            "anchored_events":anchored, "unanchored_events":len(hashes) - anchored,
            "limitation":"Signatures attest issuer statements, not execution truth. A reconciliation attests an operator's decision, not the upstream effect. An approval attests that a named operator approved or denied one exact operation, not that the operator was right. " + chain}


def load_checkpoints(path, run_id):
    """Read a witness file (one checkpoint per line) and keep this run's entries. verify checks their signatures."""
    entries = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    return [c for c in entries if isinstance(c, dict) and isinstance(c.get("body"), dict) and c["body"].get("run_id") == run_id]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    # Keys are unpadded URL-safe base64 and may begin with "-"; pass them as --public-key=KEY or by file.
    key = parser.add_mutually_exclusive_group(required=True)
    key.add_argument("--public-key"); key.add_argument("--public-key-file", type=Path)
    parser.add_argument("--checkpoints", type=Path, help="Witness file of signed checkpoints, kept apart from the evidence.")
    args = parser.parse_args()
    pinned = args.public_key if args.public_key is not None else args.public_key_file.read_text(encoding="utf-8").strip()
    try:
        evidence = json.loads(args.file.read_text(encoding="utf-8"))
        checkpoints = load_checkpoints(args.checkpoints, evidence["run"]["id"]) if args.checkpoints else ()
        if args.checkpoints and not checkpoints:
            raise ValueError("The witness file holds no checkpoint for this run")
        print(json.dumps(verify(evidence, pinned, checkpoints), indent=2))
    except MALFORMED as error:
        print(f"Verification failed: {error}", file=sys.stderr); sys.exit(1)


if __name__ == "__main__": main()
