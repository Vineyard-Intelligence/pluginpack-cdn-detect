#!/usr/bin/env node
// Syncs the CDN/WAF/hostname-pattern dataset used by this pack (src/cdn-detect.ts) from
// ProjectDiscovery's cdncheck project (MIT license): https://github.com/projectdiscovery/cdncheck
//
// `sources_data.json` also ships a `cloud` category (AWS/GCP/Azure/... hosting ranges, 120k+
// entries) — that's a different signal (cloud hosting vs. CDN/WAF edge network) and would balloon
// the bundled dataset ~35x for no benefit to CDN detection, so it's intentionally dropped here.
//
// The plugin imports the output of this script at build time and does the actual IP/hostname
// match fully offline at runtime — this script is the only thing that talks to GitHub.
//
// Usage: node scripts/sync-cdncheck-data.mjs

import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const SOURCE_URL = 'https://raw.githubusercontent.com/projectdiscovery/cdncheck/main/sources_data.json';
const KEEP_CATEGORIES = ['cdn', 'waf', 'common'];
const OUT_PATH = fileURLToPath(
    new URL('../src/data/cdncheck-data.json', import.meta.url),
);

const res = await fetch(SOURCE_URL);
if (!res.ok) throw new Error(`Fetch failed: ${res.status} ${res.statusText} (${SOURCE_URL})`);
const full = await res.json();

const trimmed = {};
for (const key of KEEP_CATEGORIES) {
    if (full[key]) trimmed[key] = full[key];
}

await writeFile(OUT_PATH, JSON.stringify(trimmed), 'utf8');

console.log(`Synced ${OUT_PATH}`);
for (const key of KEEP_CATEGORIES) {
    const category = trimmed[key] ?? {};
    const providers = Object.keys(category).length;
    const entries = Object.values(category).reduce((n, list) => n + list.length, 0);
    console.log(`  ${key}: ${providers} providers, ${entries} entries`);
}
