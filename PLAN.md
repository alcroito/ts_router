# ts-router: domain-based routing over a Headscale tailnet (TCP, UDP, ICMP)

Status: plan, nothing implemented. Investigated 2026-11-24.

## Goal

Tailnet clients reach a configured set of domains (e.g. `*.tailscale.com`) through an
egress node with no per-app config, for every IP protocol, while other traffic goes
direct. The motivating case is a laptop on a network whose filtering firewall blocks
`*.tailscale.com` by DNS and TLS SNI, while the tailnet itself (WireGuard) still works.

Requirements:

- Domain-based: no hand-maintained IP lists. CDN IPs (Vercel, CloudFront) change.
- TCP and UDP (HTTP/3, DNS, anything), ICMP as a bonus.
- Only the configured domains go via the egress node. Unrelated sites sharing a CDN IP stay
  direct.
- Works with Headscale v0.29.7 as it is (no App Connector support needed).
- No change on clients beyond normal MagicDNS + accept routes.

Non-goals (v1): multiple egress nodes, HA, per-user policy beyond a source allowlist,
replacing Tailscale App Connectors in general.

## Approach in one paragraph

A DNS server on the egress node answers queries for the configured zones with a synthetic
IP from a fixed range (`198.18.0.0/15`), one stable synthetic IP per name. Before it
answers, it resolves the real IP and stores `synthetic -> real` in an nftables map. The
egress node advertises the synthetic range as a single subnet route. Clients send packets
to the synthetic IP through the tailnet; on the egress node a kernel DNAT rule rewrites the
destination to the real IP using the map, and masquerade rewrites the source. Conntrack
handles the return path. Because this is NAT, not a proxy, every protocol works. This is
the "fake-ip" scheme of Clash/sing-box, applied to a tailnet subnet route.

```
 client (laptop)                       egress node                           internet
 ---------------                       -----------                           --------
 app: wwwv2.tailscale.com
   |  MagicDNS split DNS
   |  tailscale.com -> 100.64.0.10:53
   +------------------------------>  ts-router DNS
                                      1. upstream: wwwv2 -> 76.76.21.93
                                      2. nft map: 198.18.0.7 -> 76.76.21.93
   <------------------------------   3. answer A 198.18.0.7 (TTL 60)
 app connects 198.18.0.7:443 (TCP or UDP)
   |  route 198.18.0.0/15 via egress node (WireGuard)
   +------------------------------>  tailscale0 -> prerouting:
                                      dnat 198.18.0.7 -> 76.76.21.93
                                      forward (ts-forward accepts)
                                      postrouting: masquerade -> 203.0.113.10 ---> 76.76.21.93
   <------------------------------   conntrack reverses both NATs        <---
```

## Findings from the investigation

Environment the design was checked against: an egress node running the official Tailscale
container (kernel mode, host network, `TS_DEBUG_FIREWALL_MODE=nftables`, exit node plus
subnet routes approved via `autoApprovers`), Headscale v0.29.7, macOS and Linux clients.

- Headscale split DNS (`dns.nameservers.split`) works with nameservers at public IPs and at
  tailnet or subnet-routed IPs. Queries for a nameserver at a tailnet IP go through the
  tunnel, past the client network's filter.
- Headscale `dns.extra_records` take priority over the public answer for `tailscale.com`
  names (tested with `wwwv2.tailscale.com`).
- Forward path on the egress node: `FORWARD` (policy drop) jumps `ts-forward` first, which
  marks packets from `tailscale0*` (0x40000) and accepts them; `ts-postrouting` masquerades
  marked packets. An exit node already uses exactly this tailscale0 -> uplink path.
- `ts-forward` drops packets to `tailscale0` whose source is in `100.64.0.0/10`. Return
  packets carry the synthetic IP as source, so the synthetic range must not be in CGNAT
  space.
- Tailscale `net/routelimits` disallows routes to `100.64.0.0/10`, link-local, multicast,
  cloud metadata; `198.18.0.10` is explicitly allowed in its tests.
- Port 53 on a typical systemd host: only systemd-resolved on `127.0.0.53`/`127.0.0.54`.
  Binding the node's tailnet IPv4 and IPv6 addresses on port 53 does not conflict.
- Test host: kernel 7.2, nftables 1.1.6, other tables: docker (iptables-nft), tailscale
  chains, fail2ban. A separate `inet ts_router` table does not interfere with them.
- UDP conntrack timeouts: 30 s / 120 s (stream). Fine for QUIC and DNS.
- Tailscale's subnet SNAT means the real server sees the egress node's public IP, and
  services on the egress node behind docker see the docker gateway; neither matters here.
- tailscaled's own connections (e.g. `log.tailscale.com`) use the LAN DNS and the physical
  interface. No MagicDNS-based design changes them.
- Linux tailnet nodes do not accept routes by default. Split DNS is tailnet-wide, so a node
  using MagicDNS without accept routes would get a synthetic IP it cannot reach. The DNS
  server needs a source allowlist (see Authorization).

Prior art:

- `Matchlighter/ts-domain-gateway` (GPL-3.0, Go, ~3.8k lines, commits 2026-09-03..09):
  - Same synthetic-IP idea (`10.254.0.0/18`), one allocation per (gateway, domain), 1 h
    leases, state in sqlite/postgres.
  - Egress is a TCP proxy: iptables REDIRECT to a listener, `SO_ORIGINAL_DST`, then a PTR
    lookup against its own DNS to get the domain back, re-resolve, dial. In tsnet mode it
    uses `RegisterFallbackTCPHandler`; tsnet has no UDP equivalent, which is why it is
    TCP-only.
  - Per-source, per-domain authorization from Tailscale app capabilities (whois over the
    LocalAPI). Hand-written DNS parser; AAAA answered empty; other types passed through.
  - Ideas taken: synthetic range advertised once, stable allocation per name, persisted
    state, LocalAPI whois for optional tag-based source checks.
  - Ideas not taken: userspace proxy (no UDP, per-connection PTR + resolve), per-domain
    capability grants in the policy (needs app-capability grants and `via`).
- Tailscale App Connectors: subnet-router style, dynamic /32 routes from observed DNS.
  Headscale PR #3121 only passes the capability through; DNS steering to the connector is
  not implemented (planned around Headscale v0.31). Routing real /32s pulls in unrelated
  sites on shared CDN IPs and can race the first connection.
- Clash / sing-box "fake-ip": default ranges `198.18.0.0/15` (v4) and `fc00::/18` (v6),
  DNS hands out fake IPs, TUN maps them back. Same idea, local instead of on a router.

Libraries (versions checked 2026-11-24):

- DNS: `github.com/miekg/dns` v1.1.73 is now fixes-only and will be archived; v2 lives at
  `codeberg.org/miekg/dns`. Decide in phase 0 (see Open questions).
- nftables: `github.com/google/nftables` v0.3.0 (netlink, no `nft` binary needed). Supports
  typed maps (`ipv4_addr : ipv4_addr`), `expr.Lookup` into a register and `expr.NAT` from
  that register, and atomic batches via `Flush`.
- Config: `github.com/BurntSushi/toml` (readable, allows comments).
- No `tailscale.com` dependency in v1. Optional LocalAPI whois later over a plain HTTP
  client on the unix socket, as ts-domain-gateway does.
- Go 1.25.

## Design

### DNS server

- Listens on UDP and TCP port 53 on configured addresses (default: the node's tailnet IPv4
  and IPv6). Uses `IP_FREEBIND`/`IPV6_FREEBIND` so it can start before `tailscale0` has its
  address, and keeps working when the tailscale container restarts.
- Only answers for configured zones (suffix match: `tailscale.com` covers the apex and all
  subdomains). Anything else: `REFUSED`, so it is never an open resolver.
- Only answers sources in the allowlist; other sources get the upstream answer unchanged
  (pass-through), so nodes without accept routes keep working.
- Per query type, for a name in a zone:
  - `A`: resolve upstream (following CNAMEs), ensure allocation and map entry, then answer
    one `A` with the synthetic IP. Upstream NXDOMAIN -> NXDOMAIN. Upstream failure with a
    previous real IP -> serve stale; without one -> SERVFAIL.
  - `AAAA`: v1 answers NOERROR with no records (clients fall back to IPv4; the motivating
    network has no IPv6 anyway). v2: synthetic IPv6 (below).
  - `HTTPS` / `SVCB` (type 65/64): NOERROR, no records. Otherwise browsers could take real
    `ipv4hint`/`ipv6hint` addresses and bypass the synthetic IP.
  - Everything else (TXT, MX, CAA, NS, SOA): forward upstream unchanged.
- Answer TTL: short (default 60 s) so mapping changes and rollbacks take effect quickly.
- The map entry is written before the answer is sent, so there is no first-packet race.

### Allocation and state

- One synthetic IP per normalized name, from `198.18.0.0/15` (131,070 usable addresses),
  allocated sequentially with wrap-around.
- Entry: name, synthetic IP, real IPs, real TTL expiry, last query time.
- Persisted to a JSON file (atomic write: temp file + rename) on every new allocation and
  periodically for timestamps. Restart keeps the same synthetic IPs, so cached client
  answers stay valid.
- Garbage collection: drop entries not queried for N days (default 30). A freed synthetic
  IP is not reused for at least 1 day, well beyond any client cache of the 60 s TTL.

### Upstream resolution

- Configurable upstream list; default `1.1.1.1:53`, `1.0.0.1:53` (the egress node's own
  network is not filtered; DoH optional later). Never the host's systemd-resolved or
  MagicDNS, to avoid loops and to stay independent of host DNS config.
- Real TTL clamped to [30 s, 1 h]. On a query after expiry: re-resolve synchronously (short
  timeout), update the map, answer. A background refresher re-resolves entries queried in
  the last 24 h before they expire, so long-lived client caches do not hit stale real IPs.
- Several real IPs: v1 maps to the first one and moves to the next on refresh if it
  disappears. v2 option: `numgen`-based spread over the set.
- Existing flows keep their old real IP (conntrack), only new flows use the new one.

### nftables data path

Own table, created atomically on start (delete + recreate in one batch), left in place on
exit so flows survive a restart of ts-router:

```
table inet ts_router {
  map v4 { type ipv4_addr : ipv4_addr; }

  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "tailscale0" ip daddr 198.18.0.0/15 dnat ip to ip daddr map @v4
  }
  chain drop_unmapped {
    type filter hook prerouting priority dstnat + 10; policy accept;
    ip daddr 198.18.0.0/15 drop        # no map entry: do not leak bogon traffic
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ct original ip daddr 198.18.0.0/15 masquerade
  }
}
```

- The masquerade rule duplicates Tailscale's own subnet SNAT on purpose, so the data path
  does not depend on `--snat-subnet-routes`.
- Forwarding is already accepted by `ts-forward` (mark 0x40000 from `tailscale0`).
- Map updates are single-element batch operations; no rule reloads.
- Interface name configurable (`tailscale0`).
- Only traffic arriving on `tailscale0` is translated; packets from the internet to
  `198.18.0.0/15` are dropped by the filter chain.

### Authorization

- Who may use the synthetic range at all: Headscale ACL, e.g.
  `{"action":"accept","src":["tag:clients"],"dst":["198.18.0.0/15:*"]}`. Enforced by
  tailscaled on the egress node before packets reach the kernel.
- Who gets synthetic answers: `allow_sources` in the ts-router config (IPs/CIDRs of tailnet
  nodes). Others get pass-through answers.
- v2: tags via LocalAPI whois (`/localapi/v0/whois?addr=`), so a tag such as `tag:clients`
  can be used instead of IPs. Needs the tailscaled socket mounted.
- Optional per-zone port allowlist in nftables (`ip daddr . th dport` set) if needed later.

### IPv6 (v2)

- Synthetic v6 range from a random ULA /64 (not `fd7a:115c:a1e0::/48`, not cloud metadata
  ranges), map `ipv6_addr : ipv6_addr`, DNAT + masquerade in `ip6`. Needs public IPv6 on
  the egress node.
- Clients reach tailnet IPv6 over WireGuard even without native IPv6, so `AAAA` answers
  would work on a client network without IPv6 too. Kept for v2 because v4-only already
  covers the need.

### Config (example)

```toml
listen = ["100.64.0.10:53", "[fd7a:115c:a1e0::a]:53"]
interface = "tailscale0"
state_file = "/var/lib/ts-router/state.json"
upstreams = ["1.1.1.1:53", "1.0.0.1:53"]
answer_ttl = "60s"
synthetic_v4 = "198.18.0.0/15"
allow_sources = ["100.64.0.20/32", "100.64.0.21/32"]
gc_after = "720h"

[[zone]]
name = "tailscale.com"
```

### Commands

- `ts-router serve -config ...`: main process.
- `ts-router status`: list allocations and map entries (reads state, queries the map).
- `ts-router health`: send a DNS query to the local listener; for the compose healthcheck.
- `ts-router cleanup`: remove the nftables table.

### Deployment (example: Docker Compose on the egress node)

- Image: multi-stage Go build, `CGO_ENABLED=0`, distroless static.
- Compose service: `network_mode: host`, `cap_add: [NET_ADMIN]`, state and config volumes,
  `restart: unless-stopped`, healthcheck via `ts-router health`.
- Headscale and tailscale changes:
  - Advertise `198.18.0.0/15` from the egress node (e.g. `TS_ROUTES` for the official
    container); `autoApprovers.routes` for the egress node's tag.
  - ACL rule for the synthetic range (Authorization).
  - Split DNS: `tailscale.com: [100.64.0.10]` (the egress node's tailnet IP).
  - After cutover remove earlier workarounds such as per-IP subnet routes, `extra_records`
    entries or SNI proxies for the same names.

### Failure behaviour

- ts-router down: queries for the zones fail on allowed clients (split DNS has one
  nameserver). Mitigation: Headscale split DNS accepts several nameservers, but a second
  one returning real IPs would hand out blocked answers. Accept: if the control server runs
  on the same host, its outage already has the same effect.
- Egress node's tailscale restarting: DNS socket survives (FREEBIND), nft table untouched,
  routes come back with the node.
- Upstream down: serve stale real IPs; SERVFAIL only for names never resolved.
- State file lost: new synthetic IPs are handed out; clients holding old answers (<= 60 s)
  fail until they re-query.

## Testing plan

- Unit tests (any OS): zone matching, name normalization, allocator (stability, wrap,
  cooldown, GC), state round-trip, query-type handling with an in-memory DNS exchange and a
  fake upstream, TTL clamping, serve-stale, source allowlist.
- nftables backend behind an interface; fake for unit tests.
- Integration tests (Linux, root; build tag `integration`), run in a privileged container
  (e.g. Docker Desktop or OrbStack on macOS) or on a Linux host:
  - three network namespaces (client, router, server) joined by veth pairs, router
    interface named `tailscale0`;
  - ts-router serving on the router; client resolves a test zone via the router, then:
    TCP connect, UDP echo, ICMP ping to the synthetic IP must reach the server, and the
    server must see the router's address (masquerade);
  - unmapped synthetic IP is dropped; traffic not from `tailscale0` is not translated;
  - real IP change: new flows go to the new server IP, an open UDP flow keeps the old one.
- End-to-end on the egress node with a harmless test zone before touching `tailscale.com`:
  - `ifconfig.co` (TCP): from a client, the reported egress IP must be the egress node's;
  - `one.one.one.one` (UDP 53): `dig @one.one.one.one example.com` from a client via the
    synthetic IP;
  - HTTP/3: `curl --http3` to a QUIC-enabled host in the test zone.

## Milestones

0. Prototype without code (on the egress node, `nft` CLI + Headscale): add `198.18.0.0/15`
   route and ACL, one hand-made map entry (`198.18.0.1 -> ifconfig.co`'s IP), test
   TCP/UDP/ICMP from a client with `curl --resolve` and `dig @198.18.0.2`. Confirms the
   kernel path, `ts-forward`, masquerade and the ACL before any Go is written. Also settle
   the open questions below.
1. Core: config, allocator + state, upstream resolver, DNS server, nftables backend, unit
   tests.
2. Integration tests with network namespaces.
3. Packaging: Dockerfile, example compose file, healthcheck, deploy with the test zones.
4. Cutover of `tailscale.com`, removal of earlier workarounds, docs.
5. Optional: IPv6, tag-based sources via whois, per-zone port filters, metrics endpoint,
   multiple real IPs per name.

## Open questions (phase 0)

- miekg/dns v1 (stable, fixes-only, to be archived) vs v2 on codeberg (maintained, new API).
  Check whether v2 has a tagged stable release; pick v2 if so.
- Does the Tailscale client's MagicDNS cache honour the 60 s TTL for split-DNS answers?
- Does an `extra_records` entry still win over a split-DNS zone for the same name? (Remove
  such records at cutover either way.)
- Does a UDP socket bound with FREEBIND to the node's tailnet IP keep receiving after the
  tailscale container recreates `tailscale0`?
- Does the macOS client install the `198.18.0.0/15` route like any other subnet route
  (expected yes; routelimits allows it)?
- Any client behaviour change from answering `HTTPS` with no records (expected none).
- Does nftables' `ct original ip daddr` match work in the masquerade chain on the egress
  node's kernel as expected for DNATed flows (prototype checks it).
