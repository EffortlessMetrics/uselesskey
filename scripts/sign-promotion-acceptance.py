#!/usr/bin/env python3
"""Sign an already-reviewed promotion manifest with an explicit operator SSH key.

This is a local acceptance action. It does not perform the referenced proof,
claim live API verification, publish evidence, or change GitHub state.
"""

import argparse
import sys
from pathlib import Path

import promotion_acceptance as acceptance


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--key", type=Path, required=True,
                        help="private key, or public key whose private half is in ssh-agent")
    parser.add_argument("--valid-for-seconds", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with acceptance.initialize_output(args.output) as reservation:
            manifest = acceptance.EVIDENCE.json_object(acceptance.read_bounded(args.manifest))
            bundle = acceptance.sign_acceptance(manifest, args.identity, args.key,
                                                 args.valid_for_seconds)
            acceptance.finish_output(reservation, bundle)
        number, head, base = acceptance.manifest_subject(manifest)
        print(f"signed acceptance: {args.output}")
        print(f"retention path on {acceptance.ACCEPTANCE_REF}: "
              f"{acceptance.acceptance_path(number, head, base)}")
        print("signature authenticates acceptance; no execution or live admission claimed")
        return 0
    except (acceptance.AcceptanceError, OSError, ValueError, KeyError, TypeError,
            AttributeError, RecursionError) as exc:
        print(f"acceptance signing refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
