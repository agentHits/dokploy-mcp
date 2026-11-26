#!/usr/bin/env python3
"""Zero-trust validator for bun.lock changes against origin/<base>.

Checks performed for every lockfile path passed on the command line:
  1. Reject symlinks and NUL bytes (in both base and working tree).
  2. Reject any newly introduced external/local URL reference not already
     present in origin/<base>:<path>.
  3. Parse both base and new lockfiles with a deterministic JSONC parser
     (strips comments and trailing commas outside string literals, rejects
     duplicate JSON object keys) and require a "packages" object.
  4. Enforce fail-closed shared-key invariants (no SemVer -> non-SemVer
     tampering, no canonical package alias swap, no non-bundled -> bundled
     downgrade).
  5. Enforce the 3-layer mathematical no-downgrade invariant across all
     non-bundled SemVer 2.0.0 entries:
       - Layer 1: Per-(pkg_name, compat_line) top-aligned multiset dominance.
       - Layer 2: Per-shared-key strict 1-to-1 slot vacation + sha512 integrity
         verification on exact hoist.
       - Layer 3: Cross-bucket disappearance guard when max version drops.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import json
import os
import re
import subprocess
import sys

REF_RE = re.compile(
    r"(?i)(?:https?://|git\+|git://|ssh://|file:|github:|bitbucket:|gitlab:)[^\s\"'`<>()\[\]{},;]*"
)

SEMVER_RE = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)

SemVer = tuple[int, int, int, int, tuple[tuple[int, int | str], ...]]
CompatLine = tuple[int, ...]


@dataclass(frozen=True)
class PackageEntry:
    key: str
    pkg_name: str
    ver: str
    sv: SemVer | None
    integrity: str
    is_bundled: bool


def parse_semver(ver: str) -> SemVer | None:
    m = SEMVER_RE.fullmatch(ver)
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    pre = m.group(4)
    if pre is None:
        return (major, minor, patch, 1, ())
    pre_tuple = tuple(
        (0, int(part)) if part.isdigit() else (1, part) for part in pre.split(".")
    )
    return (major, minor, patch, 0, pre_tuple)


def compat_line(sv: SemVer) -> CompatLine:
    major, minor, patch = sv[0], sv[1], sv[2]
    if major > 0:
        return (major,)
    if minor > 0:
        return (0, minor)
    return (0, 0, patch)


def format_compat_line(cline: CompatLine) -> str:
    if len(cline) == 1:
        return f"{cline[0]}.x"
    if len(cline) == 2:
        return f"0.{cline[1]}.x"
    return f"0.0.{cline[2]}"


def strip_jsonc_comments(text: str) -> str:
    out: list[str] = []
    n = len(text)
    i = 0
    in_str = False
    escaped = False

    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            i += 1
            continue

        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                i += 2
                while i < n and text[i] != "\n":
                    i += 1
                continue
            if nxt == "*":
                i += 2
                closed = False
                while i + 1 < n:
                    if text[i] == "*" and text[i + 1] == "/":
                        i += 2
                        closed = True
                        break
                    if text[i] == "\n":
                        out.append("\n")
                    i += 1
                if not closed:
                    raise ValueError("unterminated block comment in JSONC")
                continue

        out.append(ch)
        i += 1

    return "".join(out)


def strip_trailing_commas(text: str) -> str:
    out: list[str] = []
    n = len(text)
    i = 0
    in_str = False
    escaped = False
    prev_non_ws = ""

    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
                prev_non_ws = '"'
            i += 1
            continue

        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue

        if ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]" and prev_non_ws not in ("", "{", "[", ","):
                i += 1
                continue
            out.append(ch)
            prev_non_ws = ","
            i += 1
            continue

        out.append(ch)
        if ch not in " \t\r\n":
            prev_non_ws = ch
        i += 1

    return "".join(out)


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj: dict[str, object] = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"duplicate key in bun.lock JSON: {k!r}")
        obj[k] = v
    return obj


def parse_jsonc(text: str) -> object:
    without_comments = strip_jsonc_comments(text)
    cleaned = strip_trailing_commas(without_comments)
    return json.loads(cleaned, object_pairs_hook=reject_duplicate_keys)


def split_spec(spec: str) -> tuple[str, str]:
    at_idx = spec.rfind("@")
    if at_idx > 0:
        return spec[:at_idx], spec[at_idx + 1 :]
    return spec, ""


def parse_lock_packages(text: str) -> tuple[dict[str, PackageEntry], bool]:
    data = parse_jsonc(text)
    if not isinstance(data, dict):
        raise ValueError("bun.lock root must be a JSON object")

    if "packages" not in data:
        return {}, False

    raw_packages = data["packages"]
    if not isinstance(raw_packages, dict):
        raise ValueError('"packages" section in bun.lock must be a JSON object')

    pkgs: dict[str, PackageEntry] = {}
    for key, val in raw_packages.items():
        if not isinstance(val, list) or len(val) < 1 or not isinstance(val[0], str):
            raise ValueError(f"invalid packages entry for {key!r}")
        pkg_name, ver = split_spec(val[0])
        sv = parse_semver(ver)
        is_bundled = (
            len(val) >= 3
            and isinstance(val[2], dict)
            and val[2].get("bundled") is True
        )
        integrity = val[3] if len(val) >= 4 and isinstance(val[3], str) else ""
        pkgs[key] = PackageEntry(
            key=key,
            pkg_name=pkg_name,
            ver=ver,
            sv=sv,
            integrity=integrity,
            is_bundled=is_bundled,
        )

    return pkgs, True


def is_source_vacated(
    src_e: PackageEntry,
    new_pkgs: dict[str, PackageEntry],
    pkg_name: str,
    target_cline: CompatLine,
    target_old_sv: SemVer,
) -> bool:
    if src_e.key not in new_pkgs:
        return True
    new_src = new_pkgs[src_e.key]
    if new_src.is_bundled or new_src.sv is None:
        return True
    if new_src.pkg_name != pkg_name or compat_line(new_src.sv) != target_cline:
        return True
    return new_src.sv >= target_old_sv


def validate_packages_transition(
    path: str,
    old_pkgs: dict[str, PackageEntry],
    new_pkgs: dict[str, PackageEntry],
) -> list[str]:
    errors: list[str] = []

    # Pre-layer: fail-closed checks on all shared keys (old & new).
    for key in sorted(old_pkgs.keys() & new_pkgs.keys()):
        old_e = old_pkgs[key]
        new_e = new_pkgs[key]
        if old_e.sv is not None and new_e.sv is None:
            errors.append(
                f"::error::{path}: SemVer to non-SemVer tampering forbidden for {key} "
                f"({old_e.pkg_name}@{old_e.ver} -> {new_e.pkg_name}@{new_e.ver})"
            )
            continue
        if old_e.sv is not None and old_e.pkg_name != new_e.pkg_name:
            errors.append(
                f"::error::{path}: package alias swap forbidden for {key} "
                f"({old_e.pkg_name}@{old_e.ver} -> {new_e.pkg_name}@{new_e.ver})"
            )
            continue
        if (
            not old_e.is_bundled
            and new_e.is_bundled
            and old_e.sv is not None
            and new_e.sv is not None
            and new_e.sv < old_e.sv
        ):
            errors.append(
                f"::error::{path}: downgrade via bundled transition forbidden for {key} "
                f"({old_e.ver} -> {new_e.ver})"
            )

    # Index non-bundled SemVer entries for the 3-layer invariant.
    old_buckets: dict[tuple[str, CompatLine], list[PackageEntry]] = defaultdict(list)
    new_buckets: dict[tuple[str, CompatLine], list[PackageEntry]] = defaultdict(list)
    old_by_pkg: dict[str, list[PackageEntry]] = defaultdict(list)
    new_by_pkg: dict[str, list[PackageEntry]] = defaultdict(list)

    for entry in old_pkgs.values():
        if not entry.is_bundled and entry.sv is not None:
            old_buckets[(entry.pkg_name, compat_line(entry.sv))].append(entry)
            old_by_pkg[entry.pkg_name].append(entry)

    for entry in new_pkgs.values():
        if not entry.is_bundled and entry.sv is not None:
            new_buckets[(entry.pkg_name, compat_line(entry.sv))].append(entry)
            new_by_pkg[entry.pkg_name].append(entry)

    # Layer 1: Per-(pkg_name, compat_line) top-aligned multiset dominance.
    for bucket in sorted(old_buckets.keys() & new_buckets.keys()):
        pkg_name, cline = bucket
        old_svs = sorted(e.sv for e in old_buckets[bucket] if e.sv is not None)
        new_svs = sorted(e.sv for e in new_buckets[bucket] if e.sv is not None)
        k = min(len(old_svs), len(new_svs))
        for i in range(k):
            if new_svs[-k + i] < old_svs[-k + i]:
                errors.append(
                    f"::error::{path}: Layer 1 multiset dominance violated for "
                    f"{pkg_name} ({format_compat_line(cline)})"
                )
                break

    # Layer 2: Per-shared-key strict 1-to-1 slot vacation + sha512 integrity check.
    descending_by_bucket: dict[
        tuple[str, CompatLine], list[tuple[PackageEntry, PackageEntry]]
    ] = defaultdict(list)
    for key in sorted(old_pkgs.keys() & new_pkgs.keys()):
        old_e = old_pkgs[key]
        new_e = new_pkgs[key]
        if (
            old_e.is_bundled
            or new_e.is_bundled
            or old_e.sv is None
            or new_e.sv is None
            or old_e.pkg_name != new_e.pkg_name
        ):
            continue
        if new_e.sv < old_e.sv:
            descending_by_bucket[(new_e.pkg_name, compat_line(new_e.sv))].append(
                (old_e, new_e)
            )

    for bucket, targets in sorted(descending_by_bucket.items()):
        pkg_name, cline = bucket
        # Process lowest target version first (preferring targets with integrity at ties).
        targets.sort(
            key=lambda pair: (
                pair[1].sv,
                0 if pair[1].integrity else 1,
                pair[1].key,
            )
        )
        candidates = old_buckets.get(bucket, [])
        consumed: set[str] = set()

        for old_e, new_e in targets:
            assert old_e.sv is not None and new_e.sv is not None
            eligible: list[PackageEntry] = []
            for src_e in candidates:
                assert src_e.sv is not None
                if src_e.key == new_e.key or src_e.key in consumed:
                    continue
                if src_e.sv > new_e.sv:
                    continue
                if not is_source_vacated(src_e, new_pkgs, pkg_name, cline, old_e.sv):
                    continue
                if (
                    src_e.sv == new_e.sv
                    and src_e.integrity
                    and new_e.integrity
                    and new_e.integrity != src_e.integrity
                ):
                    continue
                eligible.append(src_e)

            if not eligible:
                errors.append(
                    f"::error::{path}: downgrade forbidden for {new_e.key} "
                    f"({old_e.ver} -> {new_e.ver}): no strictly vacated compatible source"
                )
                continue

            # Pick exact-hoist matching integrity first, then highest version.
            chosen = max(
                eligible,
                key=lambda src_e: (
                    1
                    if (
                        src_e.sv == new_e.sv
                        and src_e.integrity
                        and src_e.integrity == new_e.integrity
                    )
                    else 0,
                    src_e.sv,
                    src_e.key,
                ),
            )
            consumed.add(chosen.key)

    # Layer 3: Cross-bucket disappearance guard.
    for pkg_name in sorted(old_by_pkg.keys() & new_by_pkg.keys()):
        old_entries = old_by_pkg[pkg_name]
        new_entries = new_by_pkg[pkg_name]
        old_max = max(e.sv for e in old_entries if e.sv is not None)
        new_max = max(e.sv for e in new_entries if e.sv is not None)
        if new_max < old_max:
            old_clines = {compat_line(e.sv) for e in old_entries if e.sv is not None}
            new_clines = {compat_line(e.sv) for e in new_entries if e.sv is not None}
            unexpected = sorted(new_clines - old_clines)
            if unexpected:
                formatted = ", ".join(format_compat_line(c) for c in unexpected)
                errors.append(
                    f"::error::{path}: Layer 3 cross-bucket downgrade forbidden for "
                    f"{pkg_name}: new compat line(s) [{formatted}] did not exist in base"
                )

    return errors


def validate_lockfile(base: str, path: str) -> None:
    if os.path.islink(path):
        raise SystemExit(f"::error::{path}: bun.lock must not be a symlink")

    try:
        with open(path, "rb") as fh:
            new_bytes = fh.read()
    except OSError as err:
        raise SystemExit(f"::error::{path}: failed to read file: {err}")

    if b"\x00" in new_bytes:
        raise SystemExit(f"::error::{path}: contains NUL byte (\\x00)")

    try:
        new_text = new_bytes.decode("utf-8")
    except UnicodeDecodeError as err:
        raise SystemExit(f"::error::{path}: invalid UTF-8: {err}")

    old_res = subprocess.run(
        ["git", "show", f"origin/{base}:{path}"],
        check=False,
        capture_output=True,
    )
    if old_res.returncode == 0:
        if b"\x00" in old_res.stdout:
            raise SystemExit(
                f"::error::{path}: origin/{base}:{path} contains NUL byte (\\x00)"
            )
        try:
            old_text: str | None = old_res.stdout.decode("utf-8")
        except UnicodeDecodeError as err:
            raise SystemExit(
                f"::error::{path}: origin/{base}:{path} invalid UTF-8: {err}"
            )
        allowed_refs = {m.group(0) for m in REF_RE.finditer(old_text)}
    else:
        old_text = None
        allowed_refs = set()

    if old_text is None:
        for m in REF_RE.finditer(new_text):
            found = m.group(0)
            if found not in allowed_refs:
                raise SystemExit(
                    f"::error::{path}: forbidden URL reference in new bun.lock: {found!r}"
                )
        return

    diff_res = subprocess.run(
        ["git", "diff", "-U0", "--no-color", f"origin/{base}", "--", path],
        check=False,
        capture_output=True,
        text=True,
    )
    if diff_res.returncode != 0:
        raise SystemExit(
            f"::error::{path}: git diff failed: {diff_res.stderr.strip()}"
        )

    for line in diff_res.stdout.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        content = line[1:]
        for m in REF_RE.finditer(content):
            found = m.group(0)
            if found not in allowed_refs:
                raise SystemExit(
                    f"::error::{path}: forbidden new URL reference in bun.lock: {found!r}"
                )

    try:
        old_pkgs, _ = parse_lock_packages(old_text)
        new_pkgs, new_found = parse_lock_packages(new_text)
    except ValueError as err:
        raise SystemExit(f"::error::{path}: {err}")

    if not new_found:
        raise SystemExit(f'::error::{path}: missing "packages" section in bun.lock')

    errors = validate_packages_transition(path, old_pkgs, new_pkgs)
    if errors:
        raise SystemExit("\n".join(errors))


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        raise SystemExit(
            "::error::Usage: validate-bun-lock.py <base-branch> <lockfile> [<lockfile> ...]"
        )
    base = argv[1]
    lock_files = argv[2:]
    for path in lock_files:
        validate_lockfile(base, path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
