# Lightweight DNS Security Proxy

> Inspect outbound domain requests on a local network — identify malicious traffic and intercept threats before connections are established.

## Overview

Our team will build a lightweight DNS server designed to inspect outbound domain requests on a local network, as well as identify malicious traffic and intercept threats before connections are established.

Instead of allowing client devices to resolve IP addresses directly through public providers, all network devices will route their DNS traffic through our server.

## How It Works

Our system will evaluate incoming queries in layers:

1. **Threat Intel Blocklist & Allowlist**
   - Threat intel blocklist (URLhaus, PhishTank, Malware Domain List) and local allowlist

2. **Heuristic Checks**
   - Entropy / DGA-like names
   - Typosquatting
   - Newly observed / short TTL domains

- If a query is determined to be safe, the server resolves it normally.
- If it matches malicious criteria, the server will sinkhole the request and log it.

## Logging & Evaluation

All decisions are logged to a SQLite/JSON (timestamp, client IP, domain, decision, category) for reporting and evaluation.

We will evaluate based on benign (Tranco top list) vs. malicious samples, measuring block rate, false positive/negative rate, and latency overhead vs. direct resolution.

---

## Task Delegation

| Member | Responsibility |
|---|---|
| **Toan Nguyen** | Upstream asker, forwards safe domains to google/cloudflare and returns the real IP, implements DoH, timeout/retries + fallback, and measures latency overhead. |
| **Minkyu Jeong** | Cache helper, saves past answers with expiration time and checks them first, enforces real TTL expiry, LRU eviction when full, tests hit rate/speed. |
| **Artin Seyrafi** | Block responder, returns dead IP and the threat feed updater that downloads bad domains daily, clean/normalize feeds and maintain allowlist override to avoid false positives. |
| **Justin Truong** | Banned list checker (input name string, output blocked/clean), handle subdomains (a.bad.com is part of bad.com), and make lookup efficient for 100k+ domains with speed test. |
| **Megan Tran** | Lookalike checker, essentially a typosquatting checker like paypa1.com vs paypal.com, build top 200 real list, implement edit distance, tune threshold with FP test. |
| **Chaiyun Suhr** | Gibberish checker for random DGA-like names using length and entropy score, pick threshold and evaluate on benign (Tranco) vs malicious samples. |
| **Vinh Nguyen** | Logger that saves every request, decision, and reason to SQLite (you can do MySQL or Postgres or whatever u want, but I recommend SQLite), plus design schema and provide query functions like get_top_blocked() for report generator. |
| **Kareem Saleh** | Report generator with blocked/allowed charts plus README and run instructions, run final evaluation (500 benign + 500 bad) to report block rate, FP/FN, and avg latency. |
| **Ronak Chavva** | Implement core DNS proxy engine (UDP listener, DNS wire format parsing, threaded request handling, TTL-aware cache lookup, upstream DoH forwarding, and sinkhole enforcement), plus integration for everyone else. |


## Requirements
OS, Windows, macOS, Linux
Language, Python 3
Install, pip install -r requirements.txt
Run, python main.py --port 5353
Prod, python main.py --port 53, needs admin
Test, python -m pytest tests
Login credentials, DNS service needs no login; threat feeds may require API keys
Incomplete features, see integrated implementation status below

## Integrated implementation status

`feat/proxy` contains the core engine and the production modules from all eight
component branches. The files were imported into this branch; the source
branches were not changed. IDE files and scratch scripts were excluded.

| Component | Source branch | Source commit |
|---|---|---|
| Cache | `minkyu-cache` | `4f9c061` |
| Blocklist | `feat/domain-blocklist-checker` | `1377448` |
| Sinkhole, feeds, allowlist | `artin-block-responder` | `bf2c992` |
| DGA | `feature/dga-detector` | `4cd5ec2` |
| SQLite logger | `VinhNguyen-SQLite-Logger` | `7c5cc67` |
| Upstream | `toan-upstream-asker` | `22b7b84` |
| Reporter and evaluation samples | `kareem-reporter-eval` | `9b5a6ac` |
| Typosquat algorithm and protected list | `typsquat` | `cd108c3` |

Integration fixes include a reusable typosquat interface, package-relative
imports, registrable-label comparisons, legitimate-name exclusions, and loading
`data/top200.txt` independently of the working directory. The original protected
list is preserved. Only names represented in that list receive lookalike
protection. Typosquat distance now defaults to 1. On the committed 500-domain
benign sample this flags 1 name, compared with 10 at distance 2. This sample was
used to choose the threshold, so these are not independent holdout results.

The logger exposes recent-query and cleanup helpers. Its SQLite connection and
all writes stay on one dedicated thread. The cache rejects TTLs below its
configured floor rather than extending their original lifetime.

### Run

```sh
python -m pip install -r requirements.txt
python main.py --ip 127.0.0.1 --port 5353
```

In another terminal:

```sh
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 example.com AAAA
```

Use `--ip 0.0.0.0` to bind IPv4 LAN interfaces. Ctrl+C drains pending requests
and closes owned resources. The initial transport supports IPv4 UDP only;
oversized responses are marked truncated, but client TCP retry is not served.

Optional local files are `data/blocklist.txt` and `data/allowlist.txt`, one domain
per line. They load at startup. The allowlist matches exact hostnames.
For IN A/AAAA queries, the order is allowlist override, blocklist, typosquat,
DGA, cache, upstream. Policy checks precede cache lookup. Other query types pass
through upstream without those detection checks. CNAME targets are preserved
but are not separately screened. Complex answers and EDNS/DNSSEC requests
bypass the address cache.

### Threat feeds

Configure HTTPS URLs through `URLHAUS_FEED_URL`, `PHISHTANK_FEED_URL`, or
`MDL_FEED_URL`. Alternatively, configure `URLHAUS_AUTH_KEY` or
`PHISHTANK_APP_KEY`. No sources are enabled without configuration.

Run `python -m src.feeds` to refresh a due blocklist, or add `--force` to refresh
regardless of age. Restart the proxy to load the resulting file. The updater
checks a 24-hour interval when invoked; automatic scheduling and live reload
are still outstanding.

### Tests and reporting

Run `python -m pytest tests -q -rs`. Tests cover the real components together,
concurrent loopback UDP, SQLite logging, cache expiry, sinkholes, and evaluation
edge cases. Network-dependent tests can skip when their connectivity check
fails. DGA real-data tests skip because `data/tranco_sample.txt` and
`data/dga_sample.txt` have not been supplied.

After generating query traffic:

```sh
python -m src.reporter --db logs/dns_proxy.db --out report/
```

Explicitly request the 500/500 evaluation against a running proxy with:

```sh
python -m src.reporter --evaluate --proxy-port 5353 --out report/
```

The evaluator saves `report/evaluation.json` and charts. It handles empty
NOERROR and NXDOMAIN replies, checks all answer records for sinkholes, measures
both sample groups, and reports failures and coverage separately. Undefined
rates are recorded as null. Chart output works without a desktop GUI.

The committed sample lists are inputs, not completed evaluation results.
Configure threat feeds before claiming final detection results. Do not load the
malicious evaluation list as the blocklist to manufacture a successful result.
Representative DGA datasets, final FP/FN and latency evaluation, feed scheduling,
and live reload remain outstanding.

## Promised heuristics still outstanding

**Newly observed domains** means domains first seen recently by a chosen
observer. A local implementation would persist each domain's `first_seen` time,
define whether it tracks hostnames or registrable domains, and compare age
against a configured window. Newly observed locally is different from newly
registered: an established domain can be new to this network. Registration age
requires a separate data source. A new installation also needs a learning
period, or almost every domain starts out new. See Cisco's
[newly seen domain definition](https://www.cisco.com/c/en/us/support/docs/security/umbrella/224735-enable-newly-seen-domains-security.html).

**Short TTL detection** would inspect original upstream answer TTLs and record
unusually short lifetimes as a risk signal. It must inspect upstream TTLs rather
than the remaining TTL of a cached answer. TTL describes cache lifetime, not
domain age; zero-TTL records must not be cached. See
[RFC 1035, section 3.2.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-3.2.1).
The project still needs a threshold, benign/malicious evaluation, and a decision
about whether this signal merely flags or contributes to blocking. A short TTL
alone does not establish that a domain is malicious.

Neither heuristic is implemented by the core engine. The existing TTL-aware
cache handles expiration; it is not a short-TTL threat detector.
