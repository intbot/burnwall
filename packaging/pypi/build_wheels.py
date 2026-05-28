#!/usr/bin/env python3
"""Build platform-specific PyPI wheels that wrap the prebuilt burnwall binary.

Reuses the exact binaries dist already built and attached to the GitHub Release
(downloaded into ./artifacts) -- nothing is recompiled here. For each platform we
stage that platform's binary into burnwall_launcher/_bin/ and build a wheel with
the matching platform tag, so `pip install burnwall` fetches the right one. The
binary ships as package data; a console-script entry point execs it (see
burnwall_launcher/__init__.py). Output goes to ./dist_wheels.

Only plain X.Y.Z releases are published; prerelease tags (e.g. 0.9.0-rc.1) are
skipped because they are not valid PEP 440 versions without normalization.
"""

import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"
OUT = ROOT / "dist_wheels"
BIN_DIR = HERE / "burnwall_launcher" / "_bin"
BUILD = HERE / "build"
UNPACK = HERE / "_unpack"
SETUP = HERE / "setup.py"
README = ROOT / "README.md"

VERSION = os.environ["BURNWALL_VERSION"]

# target-triple -> (archive extension, pip platform tag, binary filename)
PLATFORMS = {
    "x86_64-unknown-linux-gnu": ("tar.xz", "manylinux2014_x86_64", "burnwall"),
    "aarch64-unknown-linux-gnu": ("tar.xz", "manylinux2014_aarch64", "burnwall"),
    "x86_64-apple-darwin": ("tar.xz", "macosx_10_12_x86_64", "burnwall"),
    "aarch64-apple-darwin": ("tar.xz", "macosx_11_0_arm64", "burnwall"),
    "x86_64-pc-windows-msvc": ("zip", "win_amd64", "burnwall.exe"),
}


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def stage_binary(target, ext, binary_name):
    """Extract one release archive's binary into burnwall_launcher/_bin/."""
    archive = ARTIFACTS / f"burnwall-{target}.{ext}"
    if not archive.exists():
        fail(f"missing release archive {archive}")

    if UNPACK.exists():
        shutil.rmtree(UNPACK)
    UNPACK.mkdir(parents=True)

    if ext == "zip":
        with zipfile.ZipFile(archive) as archive_file:
            archive_file.extractall(UNPACK)
    else:
        with tarfile.open(archive) as archive_file:
            archive_file.extractall(UNPACK)

    found = next(
        (p for p in UNPACK.rglob("*")
         if p.is_file() and p.name in ("burnwall", "burnwall.exe")),
        None,
    )
    if found is None:
        fail(f"no burnwall binary inside {archive}")

    if BIN_DIR.exists():
        shutil.rmtree(BIN_DIR)
    BIN_DIR.mkdir(parents=True)
    dest = BIN_DIR / binary_name
    shutil.copy2(found, dest)
    if not binary_name.endswith(".exe"):
        dest.chmod(0o755)
    shutil.rmtree(UNPACK)


def main():
    if not re.fullmatch(r"\d+\.\d+\.\d+", VERSION):
        print(
            f"::notice title=PyPI::version '{VERSION}' is not a plain release; "
            "skipping PyPI (prerelease normalization not handled)."
        )
        return

    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    for target, (ext, platform_tag, binary_name) in PLATFORMS.items():
        stage_binary(target, ext, binary_name)

        if BUILD.exists():
            shutil.rmtree(BUILD)

        env = dict(os.environ)
        env["BURNWALL_VERSION"] = VERSION
        env["BURNWALL_README"] = str(README)

        subprocess.run(
            [
                sys.executable, str(SETUP),
                "build", "--build-base", str(BUILD),
                "bdist_wheel", "--plat-name", platform_tag,
                "--dist-dir", str(OUT),
            ],
            cwd=str(HERE),
            env=env,
            check=True,
        )

    # Don't leave a stray platform binary staged in the source tree.
    if BIN_DIR.exists():
        shutil.rmtree(BIN_DIR)

    wheels = sorted(OUT.glob("*.whl"))
    if not wheels:
        fail("no wheels were produced")
    print("built wheels:")
    for wheel in wheels:
        print(f"  {wheel.name}")


if __name__ == "__main__":
    main()
