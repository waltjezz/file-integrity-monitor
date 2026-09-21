#!/usr/bin/env python3
"""A small, standard-library-only file integrity monitoring utility."""

import argparse
import fnmatch
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

EXCLUDED_DIRS = {".git", "__pycache__", ".venv"}


def is_excluded(relative_path, patterns):
    return any(
        fnmatch.fnmatch(relative_path, pattern)
        or fnmatch.fnmatch(Path(relative_path).name, pattern)
        for pattern in patterns
    )


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan(directory, manifest_path, patterns):
    """Return {relative_path: SHA256} for regular files; skip symlinks."""
    root = directory.resolve()
    baseline = manifest_path.resolve()
    hashes = {}
    for folder, dirs, files in os.walk(root, followlinks=False):
        current = Path(folder)
        dirs[:] = sorted(
            name for name in dirs
            if name not in EXCLUDED_DIRS
            and not (current / name).is_symlink()
            and not is_excluded((current / name).relative_to(root).as_posix(), patterns)
        )
        for name in sorted(files):
            path = current / name
            relative = path.relative_to(root).as_posix()
            if (path.resolve() == baseline or path.is_symlink()
                    or not path.is_file() or is_excluded(relative, patterns)):
                continue
            try:
                hashes[relative] = sha256_file(path)
            except OSError as error:
                raise RuntimeError(f"Could not read {relative}: {error}") from error
    return hashes


def write_json_atomically(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=".fim-", suffix=".tmp", delete=False
        ) as handle:
            temp_name = handle.name
            json.dump(content, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def create_baseline(directory, manifest_path, patterns):
    files = scan(directory, manifest_path, patterns)
    baseline = {
        "format_version": 1,
        "hash_algorithm": "sha256",
        "exclude": sorted(set(patterns)),
        "files": files,
    }
    write_json_atomically(manifest_path, baseline)
    return len(files)


def compare(directory, manifest_path):
    with manifest_path.open("r", encoding="utf-8") as stream:
        baseline = json.load(stream)
    if baseline.get("format_version") != 1 or baseline.get("hash_algorithm") != "sha256":
        raise ValueError("Unsupported or invalid baseline format")
    previous = baseline["files"]
    current = scan(directory, manifest_path, baseline.get("exclude", []))
    return {
        "added": sorted(current.keys() - previous.keys()),
        "removed": sorted(previous.keys() - current.keys()),
        "modified": sorted(
            name for name in current.keys() & previous.keys()
            if current[name] != previous[name]
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Track file changes using SHA-256 hashes."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Record a trusted baseline")
    check = sub.add_parser("check", help="Compare files with the baseline")
    for subparser in (init, check):
        subparser.add_argument("directory", type=Path, help="Folder to monitor")
        subparser.add_argument("--manifest", type=Path,
                               default=Path("integrity-baseline.json"))
    init.add_argument("--exclude", action="append", default=[],
                      metavar="GLOB", help="Skip matching filenames or paths")
    args = parser.parse_args(argv)
    directory = args.directory.expanduser()
    manifest = args.manifest.expanduser().resolve()
    if not directory.is_dir():
        parser.error(f"Not a directory: {directory}")
    try:
        if args.command == "init":
            count = create_baseline(directory, manifest, args.exclude)
            print(f"Baseline saved: {count} files -> {manifest}")
            return 0
        if not manifest.is_file():
            parser.error(f"Baseline not found: {manifest}. Run init first.")
        results = compare(directory, manifest)
        for kind in ("added", "removed", "modified"):
            print(f"{kind.upper()} ({len(results[kind])}):")
            for name in results[kind]:
                print(f"  {name}")
        if any(results.values()):
            print("Changes found. Investigate before updating the baseline.")
            return 1
        print("No changes detected.")
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
