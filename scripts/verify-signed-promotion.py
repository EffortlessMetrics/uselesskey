#!/usr/bin/env python3
"""Require authenticated acceptance and current live promotion evidence.

Run from reviewed controls with independently pinned public signer bytes. No
candidate code, private signing key, or write-capable token is needed here.
"""

import argparse
import os
import sys
from pathlib import Path

import promotion_acceptance as acceptance


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", choices=sorted(acceptance.EVIDENCE.REPOSITORIES), required=True)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-base", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--from-acceptance-ref", action="store_true")
    source.add_argument("--bundle", type=Path)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--expected-signers-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with acceptance.initialize_output(args.output) as reservation:
            signers = acceptance.read_bounded(args.allowed_signers, acceptance.SIGNERS_LIMIT)
            acceptance.verify_signer_pin(signers, args.expected_signers_sha256)
            reader = acceptance.EVIDENCE.GitHubReader(os.environ.get("GITHUB_TOKEN", ""))
            provenance = None
            if args.from_acceptance_ref:
                raw, provenance = acceptance.fetch_acceptance(reader, args.repository, args.pr,
                                                              args.expected_head, args.expected_base)
            else:
                raw = acceptance.read_bounded(args.bundle)
            report = acceptance.verify_live_acceptance(
                reader, raw, signers, args.expected_signers_sha256, args.repository, args.pr,
                args.expected_head, args.expected_base, source=provenance)
            acceptance.finish_output(reservation, report)
        print(f"signed acceptance and current evidence verified: {args.output}")
        return 0
    except (acceptance.AcceptanceError, OSError, ValueError, KeyError, TypeError,
            AttributeError, RecursionError) as exc:
        print(f"signed promotion refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
