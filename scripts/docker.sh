#!/usr/bin/env bash
set -euo pipefail

# Build Docker images for server and client
# Usage: scripts/docker.sh [tag]
TAG=${1:-local}
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${ROOT_DIR}"

echo "==> Building server image: kickflip-server:${TAG}"
docker build -f Dockerfile.server -t kickflip-server:${TAG} .

echo "==> Building client image: kickflip-client:${TAG}"
docker build -f Dockerfile.client -t kickflip-client:${TAG} .

echo "Done. Images: kickflip-server:${TAG}, kickflip-client:${TAG}"
