# CDN / WAF Detection (cdncheck)

A Vineyard **plugin pack** that detects CDN/WAF providers using
[ProjectDiscovery's `cdncheck`](https://github.com/projectdiscovery/cdncheck) dataset (MIT
license) — no server, no API key, no data download beyond the bundled ranges.

Two plugins:

- **Detect CDN/WAF (IP)** — matches a selected IP against ~3,490 bundled CDN/WAF edge-network
  CIDR ranges (`cdn` + `waf` categories) and fills the node's organization field. Fully offline —
  pure CIDR-containment arithmetic, no `scopes.network` requested.
- **Detect CDN (Hostname)** — follows a selected domain's CNAME chain over DNS-over-HTTPS and
  matches it against the `common` hostname-pattern list. Adds the resolved CNAME as a
  `dns_record` node on a match.

## How it works

- **IP matching** is offline: the `cdn`/`waf` CIDR lists ship bundled in the plugin and are
  compiled into a flat range table once at load; matching returns the *most specific* (largest
  prefix) match rather than the first one found, since narrower reseller ranges can sit inside a
  broader provider's block.
- **Hostname matching** can't be done offline, since it depends on a domain's live CNAME chain, so
  it resolves over DoH (`cloudflare-dns.com`, falling back to `dns.google` — same resolvers as the
  other DoH-based Vineyard reference plugins) and matches each hop against the `common` list.

The `cloud` category (AWS/GCP/Azure hosting ranges — a different signal from CDN/WAF edge
detection) is intentionally dropped from the bundled dataset.

## Layout

- `plugins/cdn-detect.manifest.json` — the pack manifest (catalog entry source).
- `dist/` — runnable bundle (see note; not built yet — plugins run as built-ins in-app today).

Data: ProjectDiscovery `cdncheck` — <https://github.com/projectdiscovery/cdncheck> (MIT license).
