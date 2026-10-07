#!/usr/bin/env python3
"""Fail closed when a release bundle lacks a required architecture or DNS variant.

The .ipk filename is intentionally allowed to carry a human-facing
.openwrt/.glinet suffix; actual opkg identity is checked inside control.tar.gz.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tarfile

ARCHES = ("aarch64_cortex-a53", "arm_cortex-a7_neon-vfpv4", "x86_64")
VARIANTS = ("openwrt", "glinet")


def die(message: str) -> None:
    raise SystemExit(f"Release bundle verification failed: {message}")


def package_control(path: Path) -> dict[str, str]:
    try:
        with tarfile.open(path, "r:*") as ipk:
            member = ipk.extractfile("control.tar.gz")
            if member is None:
                die(f"{path.name} lacks control.tar.gz")
            with tarfile.open(fileobj=io.BytesIO(member.read()), mode="r:gz") as ctl:
                candidate = next((x for x in ctl.getmembers()
                                  if x.name.lstrip("./") == "control"), None)
                if candidate is None:
                    die(f"{path.name} lacks package control")
                raw = ctl.extractfile(candidate)
                if raw is None:
                    die(f"{path.name} has unreadable package control")
                text = raw.read().decode("utf-8")
    except (OSError, tarfile.TarError, UnicodeError) as e:
        die(f"{path.name}: {e}")
    return dict(line.split(": ", 1) for line in text.splitlines()
                if ": " in line and line[0] != " ")


def verify(path: Path, root: Path) -> None:
    digest_file = root / f"{path.name}.sha256"
    if not digest_file.is_file():
        die(f"missing checksum for {path.name}")
    text = digest_file.read_text(encoding="utf-8").strip()
    match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._~-]+)", text)
    if match is None or match.group(2) != path.name:
        die(f"invalid checksum file {digest_file.name}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != match.group(1):
        die(f"bad checksum for {path.name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--arch", choices=ARCHES, help="check one SDK artifact set")
    parser.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args()
    root: Path = args.directory.resolve()
    if not root.is_dir():
        die(f"missing directory {root}")
    arches = (args.arch,) if args.arch else ARCHES
    ipks = sorted(root.glob("*.ipk"))
    expected_names: set[str] = set()
    inventory = []

    for arch in arches:
        for prefix in ("vpn-guardian", "v2raya"):
            matches = [p for p in ipks if
                       re.fullmatch(rf"{re.escape(prefix)}_[^/]+_{arch}\.ipk", p.name)]
            if len(matches) != 1:
                die(f"expected exactly one {prefix} for {arch}; got {len(matches)}")
            path = matches[0]
            meta = package_control(path)
            if meta.get("Package") != prefix or meta.get("Architecture") != arch:
                die(f"control mismatch for {path.name}: {meta}")
            if prefix == "vpn-guardian" and "v2raya" not in meta.get("Depends", ""):
                die(f"{path.name} lacks v2raya dependency")
            if prefix == "vpn-guardian" and "dnsmasq-full" not in meta.get("Depends", ""):
                die(f"{path.name} lacks native dnsmasq-full dependency")
            expected_names.add(path.name)

        for variant in VARIANTS:
            pattern = f"dnsmasq-full_2.90-r5.1_{arch}.{variant}.ipk"
            candidates = [p for p in ipks if p.name == pattern]
            if len(candidates) != 1:
                die(f"missing dnsmasq-full {variant} package for {arch}")
            path = candidates[0]
            meta = package_control(path)
            if (meta.get("Package") != "dnsmasq-full"
                    or meta.get("Architecture") != arch
                    or meta.get("Version") != "2.90-r5.1"):
                die(f"incorrect native dnsmasq control: {path.name}: {meta}")
            expected_names.add(path.name)

    for path in ipks:
        if path.name not in expected_names and not args.arch:
            die(f"unexpected IPK {path.name}; should not publish unverified binaries")
        verify(path, root)
        buildinfo = root / f"{path.name}.buildinfo.txt"
        if not buildinfo.is_file() or not buildinfo.read_text().strip():
            die(f"missing build provenance for {path.name}")
        inventory.append({"filename": path.name,
                          "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                          "bytes": path.stat().st_size,
                          "package": package_control(path)["Package"]})

    source_names = ("v2rayA-2.5.8.tar.gz", "dnsmasq-2.90.tar.xz")
    for source in source_names:
        path = root / source
        if not path.is_file():
            die(f"missing corresponding upstream source {source}")
        verify(path, root)
    if not (root / "v2raya-2.5.8.SOURCE.txt").is_file():
        die("missing v2rayA source/license information")

    if not args.arch and len(ipks) != 12:
        die(f"expected 12 IPKs (3 targets x 4), got {len(ipks)}")
    if args.write_manifest:
        if args.arch:
            die("--write-manifest requires the full bundle")
        manifest = {
            "release": os.getenv("GITHUB_REF_NAME", "unreleased"),
            "openwrt_version": "24.10.4",
            "package_manager": "opkg",
            "sdk_targets": {
                "aarch64_cortex-a53": "mediatek/filogic",
                "arm_cortex-a7_neon-vfpv4": "ipq40xx/generic",
                "x86_64": "x86/64",
            },
            "dnsmasq_variants": list(VARIANTS),
            "files": inventory,
        }
        (root / "release-manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    print(f"Verified {len(ipks)} IPK files, native DNS variants, source archives and SHA256 hashes")


if __name__ == "__main__":
    main()
