#!/usr/bin/env python3
"""Build platform-specific PyPI wheels that wrap the prebuilt burnwall binary.

Reuses the exact binaries dist already built and attached to the GitHub Release
(downloaded into ./artifacts) -- nothing is recompiled here. Each wheel carries
one binary and the correct platform tag, so `pip install burnwall` fetches the
right one and puts it on PATH. Output goes to ./dist_wheels.

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
STAGE = HERE / "stage"
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


def extract_binary(target, ext, binary_name):
    """Pull the burnwall binary out of one release archive into STAGE."""
    archive = ARTIFACTS / f"burnwall-{target}.{ext}"
    if not archive.exists():
        fail(f"missing release archive {archive}")

    unpack = STAGE / "_unpack"
    if unpack.exists():
        shutil.rmtree(unpack)
    unpack.mkdir(parents=True)

    if ext == "zip":
        with zipfile.ZipFile(archive) as archive_file:
            archive_file.extractall(unpack)
    else:
        with tarfile.open(archive) as archive_file:
            archive_file.extractall(unpack)

    found = next(
        (p for p in unpack.rglob("*")
         if p.is_file() and p.name in ("burnwall", "burnwall.exe")),
        None,
    )
    if found is None:
        fail(f"no burnwall binary inside {archive}")

    staged = STAGE / binary_name
    shutil.copy2(found, staged)
    if not binary_name.endswith(".exe"):
        staged.chmod(0o755)
    shutil.rmtree(unpack)
    return staged


def main():
    if not re.fullmatch(r"\d+\.\d+\.\d+", VERSION):
        print(
            f"::notice title=PyPI::version '{VERSION}' is not a plain release; "
            "skipping PyPI (prerelease normalization not handled)."
        )
        return

    for directory in (OUT, STAGE):
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True)

    for target, (ext, platform_tag, binary_name) in PLATFORMS.items():
        staged = extract_binary(target, ext, binary_name)

        env = dict(os.environ)
        env["BURNWALL_BINARY"] = str(staged)
        env["BURNWALL_VERSION"] = VERSION
        env["BURNWALL_README"] = str(README)

        build_dir = STAGE / "build"
        if build_dir.exists():
            shutil.rmtree(build_dir)

        subprocess.run(
            [
                sys.executable, str(SETUP),
                "build", "--build-base", str(build_dir),
                "bdist_wheel", "--plat-name", platform_tag,
                "--dist-dir", str(OUT),
            ],
            cwd=str(HERE),
            env=env,
            check=True,
        )

        staged.unlink()  # clear before staging the next platform's binary

    wheels = sorted(OUT.glob("*.whl"))
    if not wheels:
        fail("no wheels were produced")
    print("built wheels:")
    for wheel in wheels:
        print(f"  {wheel.name}")


if __name__ == "__main__":
    main()
