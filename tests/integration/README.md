# Kickflip Integration Tests

End-to-end tests for kickflip using Docker containers in an isolated network.

## What's Tested

1. **Server Health** - Daemon starts and responds to health checks
2. **Client Registration** - Client public keys can be added to server
3. **SSH Tunnel** - Client can establish reverse SSH tunnel to server
4. **Tunnel Connectivity** - Traffic flows through the tunnel correctly
5. **Disconnect** - Clean disconnection of tunnels

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Docker Network (172.28.0.0/16)               │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │     DNS      │    │    Server    │    │ Test Runner  │      │
│  │   CoreDNS    │    │   kickflip   │    │   (client)   │      │
│  │  172.28.0.2  │    │  172.28.0.10 │    │  172.28.0.20 │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│        │                    │                   │               │
│        │   *.test.local     │    SSH tunnel     │               │
│        └────────────────────┤◄──────────────────┘               │
│                             │                                   │
└─────────────────────────────────────────────────────────────────┘
```

- **DNS (CoreDNS)**: Resolves `*.test.local` to the server container
- **Server**: Runs kickflip-server daemon with nginx and sshd
- **Test Runner**: Runs client commands and verifies behavior

## Running Tests

### Quick Start

```bash
cd tests/integration
./run-tests.sh
```

### Keep Containers for Debugging

```bash
./run-tests.sh --keep
```

Then you can:

```bash
# View logs
docker compose -f docker-compose.test.yml logs -f

# Shell into server
docker compose -f docker-compose.test.yml exec server bash

# Shell into test runner
docker compose -f docker-compose.test.yml exec test-runner bash

# Cleanup when done
docker compose -f docker-compose.test.yml down -v
```

### Run Manually

```bash
# Build containers
docker compose -f docker-compose.test.yml build

# Start environment
docker compose -f docker-compose.test.yml up

# Cleanup
docker compose -f docker-compose.test.yml down -v
```

## Test Configuration

### Server Config (`config/kickflip-server.toml`)

The test server runs in HTTP-only mode (no SSL) for simplicity:

```toml
rp_id = "test.local"
tls_enable = false
auto_cert = false
```

### DNS (`coredns/Corefile`)

CoreDNS resolves all `*.test.local` addresses to the server:

```
*.test.local -> 172.28.0.10 (server)
```

## Adding New Tests

Edit `test-runner.sh` to add new test functions:

```bash
test_my_new_feature() {
    log_info "Test N: My new feature"

    # Your test logic here

    if [ condition ]; then
        log_pass "Feature works"
    else
        log_fail "Feature broken"
        return 1
    fi
}
```

Then add the function call in `main()`.

## Troubleshooting

### Tests hang or timeout

Check if containers started properly:

```bash
docker compose -f docker-compose.test.yml ps
docker compose -f docker-compose.test.yml logs
```

### SSH tunnel fails

Shell into the test runner and try manually:

```bash
docker compose -f docker-compose.test.yml exec test-runner bash
ssh -v -i ~/.ssh/kickflip kickflip@server.test.local
```

### DNS not resolving

Check CoreDNS:

```bash
docker compose -f docker-compose.test.yml logs dns
docker compose -f docker-compose.test.yml exec test-runner nslookup test.test.local 172.28.0.2
```

### Cleanup stale containers

```bash
docker compose -f docker-compose.test.yml down -v --remove-orphans
docker network prune -f
```

## CI Integration

Add to your CI pipeline:

```yaml
integration-test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Run integration tests
      run: |
        cd tests/integration
        chmod +x run-tests.sh
        ./run-tests.sh
```
