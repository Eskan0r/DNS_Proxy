# Lightweight DNS Security Proxy

> Inspect outbound domain requests on a local network, identify malicious traffic and intercept threats before connections are established.

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

All 10 remote branches were fetched and checked on November 21, 2026, including
`main` and `feat/proxy`. Megan's new typosquat tests from `a6d30ea` were adapted
to the integrated checker API in `tests/test_typosquat.py`. The other seven
component tips are unchanged. Production behavior is integrated; source files
are not always byte-for-byte copies because compatibility fixes are preserved.

| Component | Source branch | Source commit |
|---|---|---|
| Cache | `minkyu-cache` | `4f9c061` |
| Blocklist | `feat/domain-blocklist-checker` | `1377448` |
| Sinkhole, feeds, allowlist | `artin-block-responder` | `bf2c992` |
| DGA | `feature/dga-detector` | `4cd5ec2` |
| SQLite logger | `VinhNguyen-SQLite-Logger` | `7c5cc67` |
| Upstream | `toan-upstream-asker` | `22b7b84` |
| Reporter and evaluation samples | `kareem-reporter-eval` | `9b5a6ac` |
| Typosquat algorithm, protected list, and adapted tests | `typsquat` | `a6d30ea` |

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

Ronak's assigned engine and integration work is implemented: UDP listening,
wire parsing and response validation, bounded threaded handling, TTL-aware cache
access, upstream DoH with UDP fallback, sinkhole enforcement, and all eight
component interfaces. The running engine also schedules configured feeds,
reloads policy snapshots, and records domain/TTL observations. Upstream
statistics include raw forwarding, and fallback UDP sockets accept packets
only from their configured peer.

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
per line. They load at startup and are checked for changes every 60 seconds.
The allowlist matches exact hostnames. Reloads replace the active snapshot,
so removals take effect too. Invalid/unreadable files retain the previous
snapshot; deleting a file also retains it. Publish an empty file to clear it.
Injected policy components remain owned by the caller and are not reloaded.
For IN A/AAAA queries, the order is allowlist override, blocklist, typosquat,
DGA, cache, upstream. Policy checks precede cache lookup. Other query types pass
through upstream without those detection checks. CNAME targets are preserved
but are not separately screened. Complex answers and EDNS/DNSSEC requests
bypass the address cache.

### Threat feeds

Configure HTTPS URLs through `URLHAUS_FEED_URL`, `PHISHTANK_FEED_URL`, or
`MDL_FEED_URL`. Alternatively, configure `URLHAUS_AUTH_KEY` or
`PHISHTANK_APP_KEY`. No sources are enabled without configuration.

The running proxy checks configured feeds at startup and refreshes them when
their 24-hour interval expires. Failed downloads retain the published list and
retry after five minutes. Downloads run on a separate maintenance thread and
published lists are loaded without restarting. Ctrl+C also joins this worker;
an in-progress download may need to finish or time out before shutdown completes.

Run `python -m src.feeds` to refresh a due blocklist separately, or add `--force`
to refresh regardless of age. The running proxy picks up this change on its next
policy check. Feed publication replaces `data/blocklist.txt` with the union of
configured feeds, so put exact local overrides in `data/allowlist.txt`. Configure
feed environment settings before starting the proxy.

### Tests and reporting

Run `python -m pytest tests -q -rs`. Tests cover the real components together,
concurrent loopback UDP, SQLite logging, cache expiry, sinkholes, and evaluation
edge cases. They also exercise background feed publication, live policy
replacement, persistent first-seen tracking, database migration, upstream
question matching, and latency accounting. Network-dependent tests can skip
when their connectivity check fails. DGA real-data tests skip because `data/tranco_sample.txt` and
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
Remaining team validation belongs to the component/evaluation owners: Chaiyun's
representative DGA datasets and holdout evaluation; Megan's independent
typosquat threshold evaluation; Artin's deployment feed configuration; and
Kareem's final 500/500 FP/FN and latency report. The engine and evaluator are
integrated, but these detection-quality results have not been established.

### Domain and TTL observations

These are observation-only signals stored in SQLite, separate from the blocking
decision and category. They do not change DNS responses or establish maliciousness.
Defaults are initial operational settings, not thresholds tuned on holdout data.

**Newly observed domains:** successful policy decisions for IN A/AAAA requests
record the normalized full hostname's first observation in `domain_first_seen`.
The observer is this proxy database, not an external registration service.
After a persisted 24-hour learning period, hostnames first seen less than 24
hours ago receive `newly-observed`. Both timestamps survive restarts. Existing
databases are migrated and backfilled from their previous query history.
First seen locally does not mean newly registered. Configure the learning period
and window with `NEW_DOMAIN_LEARNING_SEC` and `NEW_DOMAIN_WINDOW_SEC` in `src/config.py`.

**Short TTL:** validated, complete upstream replies record the minimum original
IN A/AAAA answer TTL in `queries.upstream_min_ttl`. Values below
`SHORT_TTL_THRESHOLD_SEC` (60 seconds, including zero) receive `short-ttl` in
`queries.risk_signals`, a JSON array. Cached remaining TTLs, sinkhole TTLs,
truncated replies, and failed responses do not feed this signal. Zero and
below-floor TTLs remain excluded from the cache.

Inspect the signals with a SQLite client:

```sql
SELECT ts, domain, decision, risk_signals, upstream_min_ttl
FROM queries WHERE risk_signals != '[]' ORDER BY rowid DESC;
```
