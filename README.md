# ts-router

DNS-driven NAT egress for a tailnet: answers configured zones with stable synthetic IPs
and maps them to the real IPs in an nftables table. Design and rationale: PLAN.md.

## Build

    go build -o ts-router ./cmd/ts-router

## Run

    ts-router serve   -config /etc/ts-router/config.toml
    ts-router status  -config ...   # allocations and nftables map state
    ts-router health  -config ...   # DNS listener answers and the table exists
    ts-router cleanup               # remove the nftables table

Needs CAP_NET_ADMIN on Linux. See the example config in PLAN.md.

## Docker

Image: `ghcr.io/alcroito/ts_router` (linux/amd64, linux/arm64).

    docker run -d --name ts-router --network host --cap-add NET_ADMIN \
        -v /srv/ts-router/config.toml:/etc/ts-router/config.toml:ro \
        -v /srv/ts-router/state:/var/lib/ts-router \
        ghcr.io/alcroito/ts_router:latest

Compose:

    services:
      ts-router:
        image: ghcr.io/alcroito/ts_router:latest
        container_name: ts-router
        network_mode: host
        cap_add: [NET_ADMIN]
        volumes:
          - ./config.toml:/etc/ts-router/config.toml:ro
          - ./state:/var/lib/ts-router
        restart: unless-stopped
        healthcheck:
          test: ["CMD", "/ts-router", "health", "-config", "/etc/ts-router/config.toml"]
          interval: 60s
          timeout: 10s
          retries: 3

Set `state_file = "/var/lib/ts-router/state.json"` in the config so state lands in the mounted directory.

## Test

Unit tests (any OS):

    go vet ./... && gofmt -l . && go test ./...

Integration tests (Linux, root, network namespaces). On macOS use a privileged container:

    docker build -t ts-router-test -f test/Dockerfile test
    docker run --rm --privileged -v "$PWD":/src -w /src ts-router-test \
        go test -tags integration -count=1 -v ./test/integration/

The run takes about a minute: the real-IP-change case waits for the 30 s minimum real TTL.
