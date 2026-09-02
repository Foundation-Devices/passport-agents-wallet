#!/usr/bin/env bash
# Create the project-local Foundation SDK mapping this repo builds against.
#
# Cargo cannot expand env vars in `path = ...` deps, so Cargo.toml points at the
# stable relative path `.foundation-sdk/current/...` and this script points that
# at your installed SDK. Run once after cloning.
#
#   ./scripts/setup-sdk.sh [/path/to/foundation-sdk-X.Y.Z-<target>]
#
# NOTE: the Foundation CLI does NOT create this mapping for you.
set -euo pipefail
cd "$(dirname "$0")/.."

DEFAULT_SDK="${FOUNDATION_SDK_ROOT:-$HOME/.foundation/sdk/foundation-sdk-1.0.0-aarch64-apple-darwin}"
SDK="${1:-$DEFAULT_SDK}"

[ -d "$SDK/lib/keyos" ] || { echo "error: no SDK at $SDK (expected $SDK/lib/keyos)"; exit 1; }

mkdir -p .foundation-sdk ui
ln -sfn "$SDK" .foundation-sdk/current
ln -sfn "$SDK/ui/ui" ui/ui

echo "SDK mapped: $SDK"
echo "Next: foundation sim   (or: cargo check)"
