#!/usr/bin/env python3
"""
Publish latest macOS installers into web/site/downloads and update latest.json.

Usage:
  python3 scripts/publish_installers.py
  python3 scripts/publish_installers.py --dist-dir client/dist --downloads-dir web/site/downloads
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import shutil
import sys
from dataclasses import dataclass


INSTALLER_RE = re.compile(
    r"^VALDEN-(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?)-(?P<arch>arm64|x64)\.(?P<fmt>dmg|zip)$"
)
INSTALLER_RE_NO_ARCH = re.compile(
    r"^VALDEN-(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?)\.(?P<fmt>dmg|zip)$"
)


@dataclass
class Installer:
    source_path: pathlib.Path
    version: str
    arch: str
    fmt: str


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def parse_version_key(version: str):
    main, _, prerelease = version.partition("-")
    parts = main.split(".")
    major = int(parts[0]) if len(parts) > 0 else 0
    minor = int(parts[1]) if len(parts) > 1 else 0
    patch = int(parts[2]) if len(parts) > 2 else 0
    is_stable = 1 if not prerelease else 0
    return (major, minor, patch, is_stable, prerelease)


def collect_installers(dist_dir: pathlib.Path) -> list[Installer]:
    installers: list[Installer] = []
    versions_with_arm64: set[tuple[str, str]] = set()

    for path in sorted(dist_dir.glob("VALDEN-*")):
        if not path.is_file():
            continue
        match = INSTALLER_RE.match(path.name)
        if match:
            version = match.group("version")
            arch = match.group("arch")
            fmt = match.group("fmt")
            installers.append(
                Installer(
                    source_path=path,
                    version=version,
                    arch=arch,
                    fmt=fmt,
                )
            )
            if arch == "arm64":
                versions_with_arm64.add((version, fmt))
            continue

        match_no_arch = INSTALLER_RE_NO_ARCH.match(path.name)
        if not match_no_arch:
            continue

        version = match_no_arch.group("version")
        fmt = match_no_arch.group("fmt")
        inferred_arch = "x64" if (version, fmt) in versions_with_arm64 else "x64"
        installers.append(
            Installer(
                source_path=path,
                version=version,
                arch=inferred_arch,
                fmt=fmt,
            )
        )
    return installers


def build_manifest(installers: list[Installer], downloads_dir: pathlib.Path) -> dict:
    if not installers:
        return {"generated_at": None, "version": None, "installers": []}

    latest_version = max((item.version for item in installers), key=parse_version_key)
    latest_by_arch_fmt: dict[tuple[str, str], Installer] = {}
    for item in installers:
        if item.version != latest_version:
            continue
        latest_by_arch_fmt[(item.arch, item.fmt)] = item

    for stale in downloads_dir.glob("VALDEN-latest-*"):
        if stale.is_file():
            stale.unlink()

    manifest_installers = []
    for (arch, fmt), item in sorted(latest_by_arch_fmt.items()):
        versioned_target = downloads_dir / item.source_path.name
        shutil.copy2(item.source_path, versioned_target)

        latest_name = f"VALDEN-latest-{arch}.{fmt}"
        latest_target = downloads_dir / latest_name
        shutil.copy2(item.source_path, latest_target)

        manifest_installers.append(
            {
                "arch": arch,
                "format": fmt,
                "version": item.version,
                "url": f"/downloads/{latest_name}",
                "filename": latest_name,
                "source_filename": item.source_path.name,
                "size_bytes": latest_target.stat().st_size,
                "sha256": sha256_file(latest_target),
            }
        )

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "version": latest_version,
        "installers": manifest_installers,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist-dir", default="client/dist", help="Path to Electron build artifacts")
    parser.add_argument("--downloads-dir", default="web/site/downloads", help="Path to website downloads directory")
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parent.parent
    dist_dir = (repo_root / args.dist_dir).resolve()
    downloads_dir = (repo_root / args.downloads_dir).resolve()
    downloads_dir.mkdir(parents=True, exist_ok=True)

    installers = collect_installers(dist_dir)
    if not installers:
        print(
            f"No installers found in {dist_dir}. Expected files like VALDEN-<version>-arm64.dmg",
            file=sys.stderr,
        )
        return 1

    manifest = build_manifest(installers, downloads_dir)
    manifest_path = downloads_dir / "latest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"Published installers to: {downloads_dir}")
    print(f"Manifest: {manifest_path}")
    print(f"Version: {manifest['version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
