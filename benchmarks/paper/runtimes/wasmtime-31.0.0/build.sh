#!/usr/bin/env bash
# Build Wasmtime release-31.0.0 from source.
# See BUILD.md. This repo documents build steps only; no binary/checksum is shipped.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
WASMTIME_SRC="${WASMTIME_SRC:-$ROOT/build/wasmtime}"
WASMTIME_TAG="${WASMTIME_TAG:-release-31.0.0}"
WASMTIME_REPO="${WASMTIME_REPO:-https://github.com/bytecodealliance/wasmtime.git}"

usage() {
    cat <<'EOF'
Usage: build.sh [clone|build|all|version]

  clone     Clone wasmtime and checkout release-31.0.0 (+ submodules)
  build     cargo build --release
  all       clone + build
  version   Print wasmtime --version (local build only)

Environment:
  WASMTIME_TAG    Git branch/tag (default: release-31.0.0)
  WASMTIME_SRC    Source directory (default: ./build/wasmtime)
EOF
}

apply_ttfi_patch() {
    local patch="$ROOT/patches/ttfi-report.patch"
    if [[ ! -f "$patch" ]]; then
        return 0
    fi
    if git -C "$WASMTIME_SRC" apply --check "$patch" 2>/dev/null; then
        git -C "$WASMTIME_SRC" apply "$patch"
        echo "Applied paper TTFI patch: $patch"
    else
        echo "Note: TTFI patch already applied or tree differs: $patch"
    fi
}

clone_source() {
    if [[ ! -d "$WASMTIME_SRC/.git" ]]; then
        git clone --depth 1 --branch "$WASMTIME_TAG" "$WASMTIME_REPO" "$WASMTIME_SRC"
    else
        git -C "$WASMTIME_SRC" fetch origin "$WASMTIME_TAG" 2>/dev/null || git -C "$WASMTIME_SRC" fetch --tags origin
        git -C "$WASMTIME_SRC" checkout "$WASMTIME_TAG"
    fi
    git -C "$WASMTIME_SRC" submodule update --init --recursive
    apply_ttfi_patch
    echo "Checked out $WASMTIME_TAG at $WASMTIME_SRC"
}

build_release() {
    if [[ -f "$HOME/.cargo/env" ]]; then
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
    fi
    command -v rustc >/dev/null 2>&1 || {
        echo "Error: rustc not found. Install Rust: https://rustup.rs/" >&2
        exit 1
    }
    cd "$WASMTIME_SRC"
    cargo build --release
    mkdir -p "$ROOT/out"
    install -m 755 "$WASMTIME_SRC/target/release/wasmtime" "$ROOT/out/wasmtime"
    echo "Built: $WASMTIME_SRC/target/release/wasmtime"
    echo "Installed: $ROOT/out/wasmtime"
}

print_version() {
    "$WASMTIME_SRC/target/release/wasmtime" --version
}

cmd="${1:-all}"
case "$cmd" in
    clone) clone_source ;;
    build) build_release ;;
    all) clone_source && build_release ;;
    version) print_version ;;
    -h|--help|help) usage ;;
    *) echo "Unknown command: $cmd" >&2; usage; exit 1 ;;
esac
