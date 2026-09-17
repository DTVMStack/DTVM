#!/usr/bin/env bash
# Shared helpers for the reproduction scripts. Source, do not execute.

# Warn (non-fatal) if the dtvm binary looks like a non-Release build.
# The paper used CMAKE_BUILD_TYPE=Release; a Debug build is far slower and
# makes every comparison misleading.
warn_if_debug_dtvm() {
  local dtvm="$1" cache bt
  [[ -x "$dtvm" ]] || return 0
  cache="$(dirname "$dtvm")/CMakeCache.txt"
  if [[ -f "$cache" ]]; then
    bt="$(grep -E '^CMAKE_BUILD_TYPE(:[A-Z]+)?=' "$cache" | head -1 | cut -d= -f2-)"
    if [[ -z "$bt" || "$bt" == "Debug" ]]; then
      echo "warning: $dtvm was built with CMAKE_BUILD_TYPE='${bt:-<empty>}' (see $cache);" >&2
      echo "         the paper used a Release build, so timings will be misleading." >&2
    fi
  elif command -v readelf >/dev/null 2>&1 && readelf -S "$dtvm" 2>/dev/null | grep -q '\.debug_info'; then
    echo "warning: $dtvm contains debug info; if it was built with CMAKE_BUILD_TYPE=Debug," >&2
    echo "         timings will be far slower than the paper's Release build." >&2
  fi
}
