// CDN / WAF Detection — matches IP addresses against known CDN/WAF edge-network ranges, and
// domains against known CDN CNAME patterns.
//
// Dataset: ProjectDiscovery's cdncheck (MIT license) — https://github.com/projectdiscovery/cdncheck
// `sources_data.json`, trimmed to `cdn` + `waf` + `common` (the much larger `cloud` category —
// AWS/GCP/Azure hosting ranges — is a different signal and is dropped; see
// scripts/sync-cdncheck-data.mjs). Re-sync with `node scripts/sync-cdncheck-data.mjs`.
//
// Two plugins, two very different network profiles:
//   1. "Detect CDN/WAF (IP)" — the `cdn`+`waf` CIDR ranges ship BUNDLED in this file (imported at
//      build time from ./data/cdncheck-data.json). Matching an IP is pure arithmetic — no fetch, no
//      CORS, no `scopes.network` at all, and no `ctx.net` capability is requested or used.
//   2. "Detect CDN (Hostname)" — the `common` list is hostname/CNAME-suffix patterns, which can only
//      be checked against a domain's *actual* CNAME chain, so this one resolves it over DNS-over-HTTPS
//      (same two resolvers as the iptoasn-cymru-doh pack — both CORS-enabled, no Worker needed).
import { definePlugin, definePluginPack } from './sdk';
import type { HostContext, RunResult, GraphNode } from './sdk';
import cdncheckData from './data/cdncheck-data.json';

type RangeMap = Record<string, string[]>; // provider -> CIDR list (or hostname-pattern list)
/*!
 * This file contains data from ProjectDiscovery cdncheck (the cdn, waf and common categories of
 * sources_data.json): https://github.com/projectdiscovery/cdncheck
 *
 * MIT License
 *
 * Copyright (c) 2021 ProjectDiscovery, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
const CDN_RANGES: RangeMap = (cdncheckData as { cdn?: RangeMap }).cdn ?? {};
const WAF_RANGES: RangeMap = (cdncheckData as { waf?: RangeMap }).waf ?? {};
const HOSTNAME_PATTERNS: RangeMap = (cdncheckData as { common?: RangeMap }).common ?? {};

// ---- CIDR containment: IPv4 via 32-bit int, IPv6 via 128-bit BigInt ------------------------
function ipv4ToInt(ip: string): number | null {
    const o = ip.split('.');
    if (o.length !== 4) return null;
    let n = 0;
    for (const part of o) {
        if (!/^\d{1,3}$/.test(part)) return null;
        const v = Number(part);
        if (v > 255) return null;
        n = (n << 8) | v;
    }
    return n >>> 0;
}

function ipv6ToBigInt(ip: string): bigint | null {
    const addr = ip.split('%')[0]; // strip zone id (fe80::1%eth0)
    if (!addr.includes(':')) return null;
    let groups: string[];
    if (addr.includes('::')) {
        if (addr.indexOf('::') !== addr.lastIndexOf('::')) return null; // only one '::' allowed
        const [h, t] = addr.split('::');
        const head = h ? h.split(':') : [];
        const tail = t ? t.split(':') : [];
        const missing = 8 - head.length - tail.length;
        if (missing < 0) return null;
        groups = [...head, ...Array(missing).fill('0'), ...tail];
    } else {
        groups = addr.split(':');
    }
    if (groups.length !== 8) return null;
    let n = 0n;
    for (const g of groups) {
        if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
        n = (n << 16n) | BigInt(parseInt(g, 16));
    }
    return n;
}

interface ParsedCidr {
    v4?: { base: number; mask: number };
    v6?: { base: bigint; bits: number };
}

function parseCidr(cidr: string): ParsedCidr | null {
    const [addr, bitsStr] = cidr.split('/');
    if (!addr || !bitsStr || !/^\d{1,3}$/.test(bitsStr)) return null; // rejects "", non-digits, "+5", "5.0", etc.
    const bits = Number(bitsStr);
    if (addr.includes(':')) {
        if (bits > 128) return null;
        const base = ipv6ToBigInt(addr);
        return base === null ? null : { v6: { base, bits } };
    }
    if (bits > 32) return null;
    const base = ipv4ToInt(addr);
    return base === null ? null : { v4: { base, mask: bits } };
}

// mask/bits === 0 (default route) is special-cased: JS's `>>>` shifts by (n mod 32), so a would-be
// `x >>> 32` silently degrades to `x >>> 0` (no-op) instead of "everything matches".
function v4Contains(range: { base: number; mask: number }, ip: number): boolean {
    if (range.mask === 0) return true;
    const shift = 32 - range.mask;
    return range.base >>> shift === ip >>> shift;
}
function v6Contains(range: { base: bigint; bits: number }, ip: bigint): boolean {
    if (range.bits === 0) return true;
    const shift = BigInt(128 - range.bits);
    return range.base >> shift === ip >> shift;
}

interface CompiledRange {
    provider: string;
    parsed: ParsedCidr;
}

// Ranges change rarely (quarterly re-sync) — parse the ~3.5k CIDR strings once at module load.
function compileRanges(byProvider: RangeMap): CompiledRange[] {
    const out: CompiledRange[] = [];
    for (const [provider, cidrs] of Object.entries(byProvider)) {
        for (const cidr of cidrs) {
            const parsed = parseCidr(cidr);
            if (parsed) out.push({ provider, parsed });
        }
    }
    return out;
}
const CDN_COMPILED = compileRanges(CDN_RANGES);
const WAF_COMPILED = compileRanges(WAF_RANGES);

// Returns the MOST SPECIFIC match (largest prefix length), not just the first one found — several
// providers publish narrow /32s that sit inside a different provider's much broader range (e.g.
// a reseller's single IP inside a cloud platform's block), so "first in JSON key order" would be
// arbitrary and could flip silently on every data re-sync.
function matchIp(ip: string, compiled: CompiledRange[]): string | null {
    const isV6 = ip.includes(':');
    const v4 = isV6 ? null : ipv4ToInt(ip);
    const v6 = isV6 ? ipv6ToBigInt(ip) : null;
    if (v4 === null && v6 === null) return null;
    let bestProvider: string | null = null;
    let bestSpecificity = -1;
    for (const { provider, parsed } of compiled) {
        if (v4 !== null && parsed.v4 && v4Contains(parsed.v4, v4) && parsed.v4.mask > bestSpecificity) {
            bestProvider = provider;
            bestSpecificity = parsed.v4.mask;
        }
        if (v6 !== null && parsed.v6 && v6Contains(parsed.v6, v6) && parsed.v6.bits > bestSpecificity) {
            bestProvider = provider;
            bestSpecificity = parsed.v6.bits;
        }
    }
    return bestProvider;
}

const isIp = (n: GraphNode) => n.type === 'infrastructure.ip_address';
const isDomain = (n: GraphNode) => n.type === 'infrastructure.domain';
const ipOf = (n: GraphNode) => String((n.data as any).ip_address ?? '').trim();
const domainOf = (n: GraphNode) => String((n.data as any).domain_name ?? '').trim();

// ---- Plugin 1: Detect CDN/WAF (IP) — zero network, pure lookup ------------------------------
const detectCdnByIp = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.cdn_detect_ip',
        content_type: 'vineyard:plugin',
        name: 'Detect CDN/WAF (IP)',
        version: '1.0.1',
        description:
            'Matches each selected IP Address against known CDN and WAF IP ranges (cdncheck) and sets the IP\'s organization to the matched provider, e.g. "cloudflare (WAF)". Unmatched IPs are left unchanged; creates no nodes.',
        icon: 'shield-check',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: { primary: 'web', web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' } },
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
            ],
            produces: [],
        },
        scopes: { graph: ['node:read', 'node:update'] },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },
    async run(ctx): Promise<RunResult> {
        const ids = ctx.input.selection;
        if (!ids.length) return { summary: 'Select one or more IP Address nodes first', counts: { matched: 0 } };

        let matched = 0;
        for (let i = 0; i < ids.length; i++) {
            if (ctx.signal?.aborted) break;
            const node = await ctx.graph!.get!(ids[i]);
            if (!node || !isIp(node)) continue;
            const ip = ipOf(node);
            if (!ip) continue;
            ctx.progress?.set?.({ percent: Math.round(((i + 1) / ids.length) * 100), message: `Checking ${ip}` });

            const cdnHit = matchIp(ip, CDN_COMPILED);
            const wafHit = matchIp(ip, WAF_COMPILED);
            if (!cdnHit && !wafHit) continue;

            // Report both hits by name when they disagree — collapsing to one name would silently
            // erase whichever provider didn't win, even though the "(CDN/WAF)" suffix implied both.
            let organization: string;
            if (cdnHit && wafHit && cdnHit !== wafHit) organization = `${cdnHit} (CDN) / ${wafHit} (WAF)`;
            else if (cdnHit && wafHit) organization = `${cdnHit} (CDN/WAF)`;
            else if (cdnHit) organization = `${cdnHit} (CDN)`;
            else organization = `${wafHit} (WAF)`;

            // Delta only: updateNode fill-merges the field we set onto live at apply time.
            // Spreading ...node.data would re-send a stale copy of every other field and overwrite
            // concurrent enrichments from other runs.
            await ctx.graph!.updateNode!(ids[i], { organization });
            matched++;
        }
        return { summary: `${matched}/${ids.length} IP(s) matched a known CDN/WAF range`, counts: { matched } };
    },
});

// ---- Plugin 2: Detect CDN (Hostname) — resolves CNAME via DoH, matches against `common` -----
const DOH_ENDPOINTS = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const MAX_CNAME_HOPS = 8;

async function dohCname(ctx: HostContext, name: string): Promise<string | null> {
    for (const base of DOH_ENDPOINTS) {
        try {
            const res = await ctx.net!.fetch!(`${base}?name=${encodeURIComponent(name)}&type=CNAME`, {
                method: 'GET',
                headers: { accept: 'application/dns-json' },
            });
            if (!res.ok) continue;
            const data = (await res.json()) as { Answer?: Array<{ type: number; data: string }> };
            const hit = (data.Answer ?? []).find((a) => a.type === 5); // 5 = CNAME
            return hit ? hit.data.replace(/\.$/, '') : null;
        } catch {
            /* try next resolver */
        }
    }
    return null;
}

/** Follows the CNAME chain up to MAX_CNAME_HOPS, returning every hostname it passes through. */
async function resolveCnameChain(ctx: HostContext, domain: string): Promise<string[]> {
    const chain: string[] = [];
    let current = domain;
    for (let hop = 0; hop < MAX_CNAME_HOPS; hop++) {
        const next = await dohCname(ctx, current);
        if (!next || chain.includes(next)) break; // no more CNAMEs, or a loop
        chain.push(next);
        current = next;
    }
    return chain;
}

// Returns the matched CNAME-chain hostname (a few source hostname patterns are listed under more
// than one provider name in the upstream data, e.g. shared/rebranded edge infra — since only the
// hostname itself is recorded on the graph (dns_record has no provider field), which provider name
// "wins" an ambiguous pattern is deliberately not tracked here; it wouldn't be used.
function matchHostname(hosts: string[]): string | null {
    for (const host of hosts) {
        const h = host.toLowerCase();
        for (const patterns of Object.values(HOSTNAME_PATTERNS)) {
            for (const p of patterns) {
                const pat = p.toLowerCase();
                if (h === pat || h.endsWith(`.${pat}`)) return host;
            }
        }
    }
    return null;
}

const detectCdnByHostname = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.cdn_detect_hostname',
        content_type: 'vineyard:plugin',
        name: 'Detect CDN (Hostname)',
        version: '1.0.2',
        description:
            'Follows each selected Domain\'s CNAME chain and matches it against known CDN hostname patterns (cdncheck). On a match, creates a CNAME DNS Record node (the matching hostname) linked "has record".',
        icon: 'route',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: { primary: 'web', web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' } },
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' },
            ],
            produces: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'dns_record' },
            ],
        },
        scopes: {
            graph: ['node:read', 'node:create', 'edge:create'],
            network: [
                {
                    endpoint: 'https://cloudflare-dns.com/dns-query',
                    methods: ['GET'],
                    purpose: 'Resolve the CNAME chain of each selected domain.',
                },
                {
                    endpoint: 'https://dns.google/resolve',
                    methods: ['GET'],
                    purpose: 'Same lookup, used when cloudflare-dns.com fails.',
                },
            ],
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },
    async run(ctx): Promise<RunResult> {
        if (!ctx.net?.fetch)
            return { summary: 'Network capability not granted to this plugin', counts: { matched: 0 } };
        const ids = ctx.input.selection;
        if (!ids.length) return { summary: 'Select one or more Domain nodes first', counts: { matched: 0 } };

        let matched = 0;
        for (let i = 0; i < ids.length; i++) {
            if (ctx.signal?.aborted) break;
            const node = await ctx.graph!.get!(ids[i]);
            if (!node || !isDomain(node)) continue;
            const domain = domainOf(node);
            if (!domain) continue;
            ctx.progress?.set?.({ percent: Math.round(((i + 1) / ids.length) * 100), message: `Resolving ${domain}` });

            const chain = await resolveCnameChain(ctx, domain);
            const matchedHost = matchHostname(chain);
            if (!matchedHost) continue;

            const dnsNode = await ctx.graph!.createNode!({
                type: 'infrastructure.dns_record',
                data: { record_name: domain, record_value: matchedHost, record_type: 'CNAME' },
            });
            await ctx.graph!.createEdge!({ from: ids[i], to: String(dnsNode.id), label: 'has record' });
            matched++;
        }
        return {
            summary: `${matched}/${ids.length} domain(s) matched a known CDN hostname pattern`,
            counts: { matched },
        };
    },
});

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.cdn_detect',
    content_type: 'vineyard:pluginpack',
    name: 'CDN / WAF Detection (cdncheck)',
    version: '1.0.4',
    description:
        "Detects CDN and WAF providers for IP addresses and domains using ProjectDiscovery's cdncheck dataset (MIT license).",
    plugins: [detectCdnByIp, detectCdnByHostname],
});
