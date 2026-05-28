"""setuptools shim that wraps a single prebuilt burnwall binary into a wheel.

Driven by build_wheels.py, which sets the environment variables below and runs
this once per platform with an explicit --plat-name. The binary is shipped via
the wheel's scripts directory, so pip installs it straight onto PATH.

The wheel is platform-specific (it carries a native binary) but NOT tied to a
Python version or ABI: the binary runs the same under any interpreter. So we
force a `py3-none-<platform>` tag rather than the `cp3XX-cp3XX-<platform>` tag
setuptools would otherwise pick for an impure wheel.
"""

import os

from setuptools import setup

try:  # setuptools >= 70.1 ships bdist_wheel itself
    from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel
except ImportError:  # older setuptools: provided by the wheel package
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel


class BdistWheel(_bdist_wheel):
    def finalize_options(self):
        super().finalize_options()
        # Not pure Python -> platform-specific wheel (honours --plat-name).
        self.root_is_pure = False

    def get_tag(self):
        # Keep the platform tag, but make it interpreter/ABI agnostic.
        _python, _abi, platform = super().get_tag()
        return "py3", "none", platform


binary = os.environ["BURNWALL_BINARY"]
version = os.environ["BURNWALL_VERSION"]

readme_path = os.environ.get("BURNWALL_README", "")
long_description = ""
if readme_path and os.path.exists(readme_path):
    with open(readme_path, encoding="utf-8") as handle:
        long_description = handle.read()

setup(
    name="burnwall",
    version=version,
    description=(
        "AI agent firewall for AI coding tools: cache-aware cost tracking, "
        "path/command security checks, and daily budget enforcement."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/intbot/burnwall",
    license="FSL-1.1-MIT",
    classifiers=[
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development",
    ],
    python_requires=">=3.8",
    # The prebuilt binary lands in the wheel's scripts dir -> installed onto PATH.
    scripts=[binary],
    cmdclass={"bdist_wheel": BdistWheel},
)
