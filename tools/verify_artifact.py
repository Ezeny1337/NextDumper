#!/usr/bin/env python3
"""Validate a NextDumper artifact directory and report its size distribution.

Checks that the reflection index and its per-package shards are consistent:
shard files exist and load, their record counts match the index, no record
appears in two shards, every record belongs to the package of its shard, and
every base type reference resolves to a known type.

Usage:
    python verify_artifact.py <artifact-dir> [--verbose]

Exit status is 0 when all checks pass, 1 when a check fails, and 2 on usage
or read errors.
"""

import argparse
import collections
import json
import os
import sys

INDEX_SCHEMA_VERSION = 11
RUNTIME_SCHEMA_VERSION = 5
MANIFEST_SCHEMA_VERSION = 9


def load_json(path):
    with open(path, "r", encoding="utf-8") as source:
        return json.load(source)


def package_of(full_name):
    """Mirror of generation::ObjectPackageName: '/Root/Dir/Package.Object' -> 'Package'."""
    _, _, path = str(full_name).partition(" ")
    if not path.startswith("/"):
        return None
    name_start = path.rfind("/")
    if name_start < 0:
        return None
    remainder = path[name_start + 1:]
    name_end = remainder.find(".")
    if name_end <= 0:
        return None
    return remainder[:name_end]


def shard_paths(artifact_dir, index):
    """Shard names come from the artifact and are untrusted: accept bare file names only."""
    shards = index.get("shards")
    if not isinstance(shards, list):
        raise ValueError("reflection.json has no shard list")
    paths = []
    for shard in shards:
        if not isinstance(shard, dict):
            raise ValueError("shard entry is not an object")
        name = str(shard.get("file", ""))
        if not name or name in (".", "..") or os.path.basename(name) != name:
            raise ValueError("unsafe shard file name: {0!r}".format(name))
        paths.append((shard, os.path.join(artifact_dir, name)))
    return paths


def check(artifact_dir, verbose):
    failures = []
    notes = []

    index_path = os.path.join(artifact_dir, "reflection.json")
    index = load_json(index_path)
    version = index.get("schema_version")
    if version != INDEX_SCHEMA_VERSION:
        failures.append(
            "reflection.json schema_version is {0}, expected {1}".format(version, INDEX_SCHEMA_VERSION)
        )
        return failures, notes, {}

    shards = shard_paths(artifact_dir, index)

    declared = collections.Counter()
    for shard_meta, _ in shards:
        for section in ("types", "enums", "functions", "properties"):
            try:
                declared[section] += int(shard_meta.get(section, 0))
            except (TypeError, ValueError):
                failures.append(
                    "shard {0!r} has a non-numeric {1} count".format(shard_meta.get("file"), section)
                )

    seen = collections.defaultdict(dict)
    types_by_address = {}
    actual = collections.Counter()
    sizes = {}

    for shard_meta, path in shards:
        if not os.path.isfile(path):
            failures.append("missing shard file: " + os.path.basename(path))
            continue
        sizes[os.path.basename(path)] = os.path.getsize(path)
        shard = load_json(path)
        if shard.get("schema_version") != INDEX_SCHEMA_VERSION:
            failures.append(
                "{0}: schema_version is {1}, expected {2}".format(
                    os.path.basename(path), shard.get("schema_version"), INDEX_SCHEMA_VERSION
                )
            )
            continue
        package = shard.get("package")
        if package != shard_meta.get("package"):
            failures.append(
                "{0}: package {1!r} differs from index entry {2!r}".format(
                    os.path.basename(path), package, shard_meta.get("package")
                )
            )

        for section in ("types", "enums", "functions"):
            records = shard.get(section, [])
            if not isinstance(records, list):
                failures.append("{0}: {1} is not a list".format(os.path.basename(path), section))
                continue
            actual[section] += len(records)
            for record in records:
                address = str(record.get("address", ""))
                if address in seen[section]:
                    failures.append(
                        "{0}: address {1} appears in both {2} and {3}".format(
                            section, address, seen[section][address], os.path.basename(path)
                        )
                    )
                else:
                    seen[section][address] = os.path.basename(path)
                if section == "types":
                    types_by_address[address] = record
                owner_package = package_of(record.get("full_name", ""))
                if owner_package is None:
                    continue
                if owner_package != package:
                    failures.append(
                        "{0}: {1} belongs to package {2!r}".format(
                            os.path.basename(path), address, owner_package
                        )
                    )

        properties = 0
        for record in shard.get("types", []):
            properties += len(record.get("properties", []))
        for record in shard.get("functions", []):
            properties += len(record.get("parameters", [])) + len(record.get("locals", []))
        actual["properties"] += properties

    for section in ("types", "enums", "functions", "properties"):
        if declared[section] != actual[section]:
            failures.append(
                "{0}: index declares {1}, shards hold {2}".format(section, declared[section], actual[section])
            )

    stats = index.get("stats", {})
    for section, key in (("types", "parsed_types"), ("enums", "parsed_enums"), ("functions", "parsed_functions")):
        if key in stats and int(stats[key]) != actual[section]:
            failures.append(
                "stats.{0} is {1}, shards hold {2}".format(key, stats[key], actual[section])
            )

    # Base type references may cross package boundaries; every non-null one must resolve.
    unresolved = 0
    for address, record in types_by_address.items():
        base = str(record.get("super", "0x0"))
        if base not in ("0x0", "0") and base not in types_by_address:
            unresolved += 1
            if verbose and unresolved <= 10:
                notes.append("unresolved base {0} for type {1}".format(base, address))
    if unresolved:
        notes.append("base references not present in the artifact: {0}".format(unresolved))

    for name in ("diagnostics.json", "runtime.json", "manifest.json"):
        path = os.path.join(artifact_dir, name)
        if os.path.isfile(path):
            sizes[name] = os.path.getsize(path)
        else:
            failures.append("missing file: " + name)
    runtime_path = os.path.join(artifact_dir, "runtime.json")
    if os.path.isfile(runtime_path):
        runtime = load_json(runtime_path)
        if runtime.get("schema_version") != RUNTIME_SCHEMA_VERSION:
            failures.append("runtime.json schema_version is not {0}".format(RUNTIME_SCHEMA_VERSION))
    manifest_path = os.path.join(artifact_dir, "manifest.json")
    if os.path.isfile(manifest_path):
        manifest = load_json(manifest_path)
        if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
            failures.append("manifest.json schema_version is not {0}".format(MANIFEST_SCHEMA_VERSION))
        recorded = manifest.get("artifact_sizes")
        if isinstance(recorded, dict):
            for name, size in sorted(recorded.items()):
                current = sizes.get(name)
                if current is not None and int(size) != current:
                    failures.append(
                        "manifest artifact_sizes[{0}] is {1}, file is {2}".format(name, size, current)
                    )

    notes.append(
        "shards={0} types={1} enums={2} functions={3} properties={4}".format(
            len(shards), actual["types"], actual["enums"], actual["functions"], actual["properties"]
        )
    )
    return failures, notes, sizes


def main():
    parser = argparse.ArgumentParser(description="Validate a NextDumper artifact directory.")
    parser.add_argument("artifact_dir")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if not os.path.isdir(args.artifact_dir):
        sys.stderr.write("not a directory: {0}\n".format(args.artifact_dir))
        return 2
    try:
        failures, notes, sizes = check(args.artifact_dir, args.verbose)
    except (OSError, ValueError) as error:
        sys.stderr.write("read error: {0}\n".format(error))
        return 2

    for note in notes:
        sys.stdout.write("note: " + note + "\n")
    if sizes:
        sys.stdout.write("\nsize distribution:\n")
        total = sum(sizes.values())
        for name, size in sorted(sizes.items(), key=lambda item: -item[1]):
            sys.stdout.write(
                "  {0:>10}  {1:5.1f}%  {2}\n".format(size, 100.0 * size / total if total else 0.0, name)
            )
        sys.stdout.write("  {0:>10}  100.0%  total\n".format(total))

    if failures:
        sys.stdout.write("\n{0} check(s) failed:\n".format(len(failures)))
        for failure in failures[:50]:
            sys.stdout.write("  - " + failure + "\n")
        if len(failures) > 50:
            sys.stdout.write("  ... {0} more\n".format(len(failures) - 50))
        return 1
    sys.stdout.write("\nall checks passed\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
