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

## Test

Unit tests (any OS):

    go vet ./... && gofmt -l . && go test ./...

Integration tests (Linux, root, network namespaces). On macOS use a privileged container:

    docker build -t ts-router-test -f test/Dockerfile test
    docker run --rm --privileged -v "$PWD":/src -w /src ts-router-test \
        go test -tags integration -count=1 -v ./test/integration/

The run takes about a minute: the real-IP-change case waits for the 30 s minimum real TTL.
