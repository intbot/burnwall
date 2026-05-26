#!/usr/bin/env bash
#
# setup-private.sh — link this repo's private working folder into ./private/
#
# Derives the project name from the current git repository, looks for a
# matching folder at ~/private/<project>/, and symlinks it to ./private/.
# The ./private/ path is gitignored, so anything you keep there stays local.
#
# Works on Linux, macOS, and Windows (Git Bash / MSYS2 / Cygwin).
# Fails gracefully — if there is no matching folder, it just says so.

set -euo pipefail

# --- locate the repo and derive the project name -----------------------------

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$repo_root" ]; then
  echo "setup-private: not inside a git repository — nothing to link." >&2
  exit 1
fi

project="$(basename "$repo_root")"
source_dir="$HOME/private/$project"
target_dir="$repo_root/private"

# --- bail out cleanly if there is nothing to link ----------------------------

if [ ! -d "$source_dir" ]; then
  echo "setup-private: no private folder found at '$source_dir'."
  echo "               create it first if you want a local private area:"
  echo "                 mkdir -p \"$source_dir\""
  exit 0
fi

# --- handle an existing ./private/ -------------------------------------------

if [ -L "$target_dir" ]; then
  current="$(readlink "$target_dir" 2>/dev/null || true)"
  echo "setup-private: ./private already links to '${current:-?}' — leaving it as is."
  exit 0
fi

if [ -e "$target_dir" ]; then
  echo "setup-private: ./private already exists and is not a symlink — refusing to touch it." >&2
  exit 1
fi

# --- create the symlink (OS-aware) -------------------------------------------

case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*)
    # Windows: ln -s under Git Bash often copies instead of linking, so use
    # the native mklink with Windows-style paths.
    win_target="$(cygpath -w "$target_dir")"
    win_source="$(cygpath -w "$source_dir")"
    if ! cmd //c mklink /D "$win_target" "$win_source" >/dev/null; then
      echo "setup-private: failed to create symlink." >&2
      echo "               on Windows this needs Developer Mode or an elevated shell." >&2
      exit 1
    fi
    ;;
  *)
    ln -s "$source_dir" "$target_dir"
    ;;
esac

echo "setup-private: linked ./private -> $source_dir"
