#!/usr/bin/env bash
set -euo pipefail

# Release script using cross (Docker-based) to build for multiple targets
# Prereqs: cargo, cross (`cargo install cross`), Docker/Podman
# On macOS, this script also builds native darwin targets with cargo.

# For Linux targets on Apple Silicon/macOS, ensure we pull/run amd64 cross images via emulation
export DOCKER_DEFAULT_PLATFORM=${DOCKER_DEFAULT_PLATFORM:-linux/amd64}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
OS_NAME="$(uname -s)"

LINUX_TARGETS=(
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
)

# Only used on macOS
DARWIN_TARGETS=(
  aarch64-apple-darwin
  x86_64-apple-darwin
)

BINARIES=(kickflip-server daemon kickflip-client)

if ! command -v cross >/dev/null 2>&1; then
  echo "cross is not installed. Install with: cargo install cross" >&2
  exit 1
fi

# Pre-install rustup targets to satisfy cross/rustup toolchain checks.
if command -v rustup >/dev/null 2>&1; then
  echo "==> Ensuring rustup targets are installed"
  for t in "${LINUX_TARGETS[@]}"; do
    rustup target add "$t" || true
  done
  if [[ "${OS_NAME}" == "Darwin" ]]; then
    for t in "${DARWIN_TARGETS[@]}"; do
      rustup target add "$t" || true
    done
  fi
fi

mkdir -p "${DIST_DIR}"

build_linux_target() {
  local target="$1"
  echo "==> Building Linux target: ${target}"
  cross build -r --target "${target}" -p kickflip-server
  cross build -r --target "${target}" -p kickflip-server --bin daemon
  cross build -r --target "${target}" -p kickflip-client

  local out_dir="${DIST_DIR}/${target}"
  mkdir -p "${out_dir}"
  for bin in "${BINARIES[@]}"; do
    cp -v "${ROOT_DIR}/target/${target}/release/${bin}" "${out_dir}/" 2>/dev/null || {
      echo "Missing binary: ${bin} for ${target}" >&2
      exit 1
    }
  done

  local tarball="${DIST_DIR}/kickflip-${target}.tar.gz"
  tar -C "${out_dir}" -czf "${tarball}" ${BINARIES[*]}
  echo "Packaged: ${tarball}"
}

build_darwin_target() {
  local target="$1"
  echo "==> Building macOS target: ${target}"
  cargo build -r --target "${target}" -p kickflip-server
  cargo build -r --target "${target}" -p kickflip-server --bin daemon
  cargo build -r --target "${target}" -p kickflip-client

  local out_dir="${DIST_DIR}/${target}"
  mkdir -p "${out_dir}"
  for bin in "${BINARIES[@]}"; do
    cp -v "${ROOT_DIR}/target/${target}/release/${bin}" "${out_dir}/" 2>/dev/null || {
      echo "Missing binary: ${bin} for ${target}" >&2
      exit 1
    }
  done

  local tarball="${DIST_DIR}/kickflip-${target}.tar.gz"
  tar -C "${out_dir}" -czf "${tarball}" ${BINARIES[*]}
  echo "Packaged: ${tarball}"
}

# Linux builds via cross
for t in "${LINUX_TARGETS[@]}"; do
  build_linux_target "${t}"
done

# macOS builds (native cargo) if running on macOS host
if [[ "${OS_NAME}" == "Darwin" ]]; then
  for t in "${DARWIN_TARGETS[@]}"; do
    build_darwin_target "${t}"
  done

  # Optional: produce universal2 binaries if both archs built and lipo is available
  if command -v lipo >/dev/null 2>&1; then
    echo "==> Creating universal2 macOS binaries"
    local_universal_dir="${DIST_DIR}/universal2-macos"
    mkdir -p "${local_universal_dir}"
    for bin in "${BINARIES[@]}"; do
      lipo -create \
        "${ROOT_DIR}/target/aarch64-apple-darwin/release/${bin}" \
        "${ROOT_DIR}/target/x86_64-apple-darwin/release/${bin}" \
        -output "${local_universal_dir}/${bin}"
      echo "Created universal2: ${bin}"
    done
    local tarball="${DIST_DIR}/kickflip-universal2-macos.tar.gz"
    tar -C "${local_universal_dir}" -czf "${tarball}" ${BINARIES[*]}
    echo "Packaged: ${tarball}"
  fi
fi

echo "\nAll artifacts are in: ${DIST_DIR}"
