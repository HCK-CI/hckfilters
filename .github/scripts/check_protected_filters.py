#!/usr/bin/env python3
"""
CI guard for filters used in our certification.

Policy:
- The source of truth is `protected_filters.json` (committed in the repo). It lists filters that are used in our
  certification and must not disappear unexpectedly.
- Each entry specifies an explicit `(filterNumber, version)` to protect.
- The check compares the PR base vs PR head:
  - If a protected `(filterNumber, version)` exists in the PR base but is missing in the PR head, we fail the PR.
    This catches both a real deletion and a version bump (e.g. base has v8 but the PR has only v9).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple


HEADER_RE = re.compile(r"^--\s+Inserting\s+filter\s+(\d+)\s+v(\d+)\.\s*$")


@dataclass(frozen=True)
class FilterKey:
    number: int
    version: int

    def __str__(self) -> str:
        return f"{self.number} v{self.version}"


def _git_show_text(sha: str, path: str) -> str:
    try:
        out = subprocess.check_output(["git", "show", f"{sha}:{path}"], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        msg = e.output.decode("utf-8", errors="replace")
        raise RuntimeError(f"Failed to read {path!r} from git revision {sha!r}.\n{msg}") from e
    return out.decode("utf-8", errors="replace")


def parse_filter_keys(sql_text: str) -> Set[FilterKey]:
    """
    Return a set of (FilterNumber, Version) keys present in UpdateFilters.sql.

    We parse headers like:
      -- Inserting filter <number> v<version>.
    """
    sql_text = sql_text.replace("\r\n", "\n").replace("\r", "\n")
    keys: Set[FilterKey] = set()
    for line in sql_text.split("\n"):
        m = HEADER_RE.match(line)
        if m:
            keys.add(FilterKey(number=int(m.group(1)), version=int(m.group(2))))
    return keys


def load_protected_filter_keys(path: Path) -> List[FilterKey]:
    """
    Load protected filters from protected_filters.json.

    One version per filterNumber is enforced (duplicates are rejected).
    """
    data = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(data, dict) and "filters" in data and isinstance(data["filters"], list):
        entries = data["filters"]
    else:
        raise ValueError(
            "protected_filters.json must contain 'filters'[] (array of objects with 'filterNumber' and 'version')"
        )

    protected_keys: List[FilterKey] = []
    seen_numbers: Set[int] = set()

    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Each filters[] entry must be an object")
        if "filterNumber" not in entry or "version" not in entry:
            raise ValueError("Each filters[] entry must contain 'filterNumber' and 'version'")
        filter_number = int(entry["filterNumber"])
        version = int(entry["version"])
        if filter_number in seen_numbers:
            raise ValueError(f"Duplicate filterNumber in protected_filters.json: {filter_number}")
        seen_numbers.add(filter_number)
        protected_keys.append(FilterKey(filter_number, version))

    return protected_keys


def main(argv: List[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--protected", required=True, help="Path to protected_filters.json")
    p.add_argument("--sql", default="UpdateFilters.sql", help="Path to UpdateFilters.sql in repo")
    p.add_argument("--base-sha", required=True, help="PR base commit SHA")
    p.add_argument("--head-sha", required=True, help="PR head commit SHA")
    args = p.parse_args(argv)

    protected_path = Path(args.protected)
    if not protected_path.exists():
        print(f"ERROR: protected file not found: {protected_path}", file=sys.stderr)
        return 2

    protected_keys_from_json = load_protected_filter_keys(protected_path)

    base_sql = _git_show_text(args.base_sha, args.sql)
    head_sql = _git_show_text(args.head_sha, args.sql)

    base_keys = parse_filter_keys(base_sql)
    head_keys = parse_filter_keys(head_sql)

    # Enforce only protected keys that exist in the PR base; otherwise warn.
    enforced_protected_keys: List[FilterKey] = []
    missing_protected_keys_in_base: List[FilterKey] = []

    for protected_key in protected_keys_from_json:
        if protected_key in base_keys:
            enforced_protected_keys.append(protected_key)
        else:
            missing_protected_keys_in_base.append(protected_key)
            print(
                f"::warning::Protected filter {protected_key} not found in PR base ({args.base_sha[:8]}).",
                file=sys.stderr,
            )

    missing_protected_keys_in_head: List[FilterKey] = []

    for key in enforced_protected_keys:
        # Fail if a protected key is missing in the PR head.
        if key not in head_keys:
            missing_protected_keys_in_head.append(key)

    if missing_protected_keys_in_base:
        print(
            "NOTE: some protected filters from protected_filters.json were not found in the PR base and therefore were not enforced:\n"
            + "\n".join(
                f"  - {k}"
                for k in sorted(missing_protected_keys_in_base, key=lambda k: k.number)
            ),
            file=sys.stderr,
        )

    if not missing_protected_keys_in_head:
        print(
            f"OK: no protected filters were deleted or had version changes ({len(enforced_protected_keys)} protected blocks checked)."
        )
        return 0

    print("ERROR: protected filters are missing (deleted or version-bumped).", file=sys.stderr)
    print("\nMissing protected filter blocks (from PR base):", file=sys.stderr)
    for missing_key in sorted(missing_protected_keys_in_head, key=lambda k: k.number):
        head_versions = sorted({hk.version for hk in head_keys if hk.number == missing_key.number})
        if head_versions:
            detail = (
                f"{missing_key} is missing; PR head contains filter {missing_key.number} "
                f"with versions {head_versions} (version bump/change)"
            )
        else:
            detail = f"{missing_key} is missing; filterNumber {missing_key.number} is not present in PR head (likely deleted)"
        print(f"::error title=Protected filter missing::{detail}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))


