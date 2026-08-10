"""Scan only tracked files and blobs reachable from explicitly supplied refs."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from publication_policy import content_issues, path_issue


def _git(root: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        input=input_bytes,
        check=False,
        capture_output=True,
        timeout=120,
    )
    if completed.returncode != 0:
        raise RuntimeError("publication history Git operation failed")
    return completed.stdout


def _record(
    issues: list[tuple[str, str]],
    location: str,
    path: str,
    data: bytes,
) -> None:
    category = path_issue(path)
    if category is not None:
        issues.append((location, category))
    issues.extend((location, category) for category in content_issues(data))


def scan(root: Path, refs: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """Return redacted ``(location, category)`` findings."""
    root = root.resolve()
    issues: list[tuple[str, str]] = []
    tracked = _git(root, "ls-files", "-z").split(b"\0")
    for raw_path in tracked:
        if not raw_path:
            continue
        path = raw_path.decode("utf-8", "surrogateescape")
        candidate = root / path
        if candidate.is_file():
            _record(issues, f"tracked:{path}", path, candidate.read_bytes())

    objects: dict[str, set[str]] = {}
    commits = _git(root, "rev-list", *refs).splitlines()
    for raw_commit in commits:
        commit = raw_commit.decode("ascii")
        tree = _git(root, "ls-tree", "-r", "-z", "--full-tree", commit)
        for record in tree.split(b"\0"):
            if not record:
                continue
            header, separator, raw_path = record.partition(b"\t")
            fields = header.split()
            if not separator or len(fields) != 3 or fields[1] != b"blob":
                continue
            object_id = fields[2].decode("ascii")
            path = raw_path.decode("utf-8", "surrogateescape")
            objects.setdefault(object_id, set()).add(path)

    for object_id, paths in objects.items():
        data = _git(root, "cat-file", "blob", object_id)
        first_path = min(paths)
        issues.extend(
            (f"history:{object_id[:12]}:{first_path}", category)
            for category in content_issues(data)
        )
        for path in paths:
            category = path_issue(path)
            if category is not None:
                issues.append((f"history:{object_id[:12]}:{path}", category))
    return tuple(dict.fromkeys(issues))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ref", action="append", required=True, dest="refs")
    args = parser.parse_args()
    issues = scan(args.repository, tuple(args.refs))
    if issues:
        for location, category in issues:
            print(f"publication safety issue: location={location} category={category}")
        return 1
    print("publication history safety: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
