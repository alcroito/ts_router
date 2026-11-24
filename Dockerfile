# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.25 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w" -o /out/ts-router ./cmd/ts-router

# Root variant: the tool needs CAP_NET_ADMIN and binds port 53, which nonroot cannot do.
FROM gcr.io/distroless/static-debian12
LABEL org.opencontainers.image.source="https://github.com/alcroito/ts_router" \
      org.opencontainers.image.description="DNS-driven NAT egress for a tailnet"
COPY --from=build /out/ts-router /ts-router
ENTRYPOINT ["/ts-router"]
CMD ["serve", "-config", "/etc/ts-router/config.toml"]
