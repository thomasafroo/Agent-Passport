"""Offline integrity verification with an independently pinned issuer key."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_passport.core import canonical, verify_receipt


def verify(evidence, pinned_key):
    if evidence.get("public_key") != pinned_key:
        raise ValueError("Issuer does not match pinned key")
    previous = "0" * 64
    for event in evidence["events"]:
        body = {k:v for k,v in event.items() if k not in {"seq", "hash"}}
        if body["previous"] != previous or hashlib.sha256(canonical(body)).hexdigest() != event["hash"]:
            raise ValueError("Event chain is altered or reordered")
        previous = event["hash"]
    for receipt in evidence["receipts"]:
        if not verify_receipt(receipt, pinned_key):
            raise ValueError("Invalid receipt signature")
        if receipt["body"]["run_id"] != evidence["run"]["id"]:
            raise ValueError("Receipt belongs to another run")
    return {"valid": True, "events":len(evidence["events"]), "receipts":len(evidence["receipts"]), "head":previous,
            "limitation":"Signatures attest issuer statements, not execution truth. An unanchored event chain cannot prove completeness or prevent wholesale rewriting."}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    # Keys are unpadded URL-safe base64 and may begin with "-"; pass them as --public-key=KEY or by file.
    key = parser.add_mutually_exclusive_group(required=True)
    key.add_argument("--public-key"); key.add_argument("--public-key-file", type=Path)
    args = parser.parse_args()
    pinned = args.public_key if args.public_key is not None else args.public_key_file.read_text(encoding="utf-8").strip()
    try: print(json.dumps(verify(json.loads(args.file.read_text(encoding="utf-8")), pinned), indent=2))
    except (ValueError, KeyError, TypeError) as error:
        print(f"Verification failed: {error}", file=sys.stderr); sys.exit(1)


if __name__ == "__main__": main()
