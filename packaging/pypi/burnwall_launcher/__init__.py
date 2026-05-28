"""Console-script launcher for the bundled native burnwall binary.

Each wheel ships the platform's prebuilt binary inside this package (``_bin/``).
The ``burnwall`` console-script entry point calls :func:`main`, which execs that
binary with the same arguments and returns its exit code.

Using an entry point (rather than setuptools ``scripts=``) keeps wheel building
robust across setuptools / Python versions: a raw binary placed in ``scripts=``
breaks newer setuptools, which reads scripts as text to patch shebangs and
chokes on the binary's null bytes.
"""

import os
import subprocess
import sys


def _binary_path():
    here = os.path.dirname(os.path.abspath(__file__))
    name = "burnwall.exe" if os.name == "nt" else "burnwall"
    return os.path.join(here, "_bin", name)


def main():
    path = _binary_path()
    if not os.path.exists(path):
        sys.stderr.write(f"burnwall: bundled binary not found at {path}\n")
        return 70  # EX_SOFTWARE
    if os.name != "nt":
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass  # best effort; pip usually preserves the mode already
    return subprocess.run([path, *sys.argv[1:]]).returncode


if __name__ == "__main__":
    sys.exit(main())
