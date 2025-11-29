#!/bin/bash
# Run kickflip integration tests
#
# Usage:
#   ./run-tests.sh         # Run tests and cleanup
#   ./run-tests.sh --keep  # Run tests but keep containers for debugging
#
# Requirements:
#   - Docker
#   - Docker Compose v2+

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

KEEP_CONTAINERS=false

# Parse args
for arg in "$@"; do
    case $arg in
        --keep)
            KEEP_CONTAINERS=true
            shift
            ;;
    esac
done

cleanup() {
    if [ "$KEEP_CONTAINERS" = false ]; then
        echo -e "${YELLOW}Cleaning up containers...${NC}"
        docker compose -f docker-compose.test.yml down -v --remove-orphans 2>/dev/null || true
    else
        echo -e "${YELLOW}Keeping containers for debugging.${NC}"
        echo "To view logs: docker compose -f docker-compose.test.yml logs"
        echo "To shell into server: docker compose -f docker-compose.test.yml exec server bash"
        echo "To cleanup: docker compose -f docker-compose.test.yml down -v"
    fi
}

trap cleanup EXIT

echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}  Kickflip Integration Tests${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""

echo -e "${YELLOW}Building containers...${NC}"
docker compose -f docker-compose.test.yml build

echo ""
echo -e "${YELLOW}Starting test environment...${NC}"
docker compose -f docker-compose.test.yml up \
    --abort-on-container-exit \
    --exit-code-from test-runner

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✅ Integration tests passed!${NC}"
else
    echo ""
    echo -e "${RED}❌ Integration tests failed (exit code: $EXIT_CODE)${NC}"
fi

exit $EXIT_CODE

