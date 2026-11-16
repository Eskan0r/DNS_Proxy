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
Login credentials, none needed
Incomplete features, see implementation status below

## Core proxy implementation status

The core UDP engine, command-line startup, and shared domain helpers are
implemented on `feat/proxy`. The default server requires the separate component
branches to be integrated first. This branch alone deliberately exits with a
component initialization error because main's cache and detection modules are
still stubs. It does not silently disable missing security layers.

After integration, run `python main.py --ip 127.0.0.1 --port 5353` and test with
`dig @127.0.0.1 -p 5353 example.com A`. Use `--ip 0.0.0.0` to bind IPv4 LAN
interfaces. Ctrl+C drains pending requests and closes owned resources.

Integration contracts:

- Use the component branches' `DNSCache`, `BlocklistChecker`, `Allowlist`,
  `DGADetector`, `UpstreamResolver`, and `QueryLogger` implementations.
- Typosquatting must support `TyposquatChecker()`,
  `load_top_file(path) -> count`, and
  `is_lookalike(domain) -> (blocked, target, distance)`. Megan's current branch
  still needs the interface, import, and lookup fixes described in the audit.
- Provide `data/top200.txt` for the default typosquat loader. Load an optional
  `data/blocklist.txt` at startup; `Allowlist` owns `data/allowlist.txt` loading.
  Keep the feed configuration additions, DGA threshold, and `tldextract`
  dependency when combining branches.
- Upstream requests use `forward(wire_bytes) -> wire_bytes`. This preserves
  CNAMEs, negative answers, response codes, and non-address records.
- Logging uses a dedicated thread so Vinh's current SQLite connection is
  created, used, and closed on the same thread.

For IN A/AAAA queries, the order is allowlist override, blocklist, typosquat,
DGA, cache, upstream. Policy checks run before the cache so newly blocked
domains cannot be served from old cache entries. Other record types pass
through upstream without these detection checks, as scoped for the initial
engine. CNAME targets are preserved but are not separately screened.

Only simple address answers enter the cache. Cached TTLs count down. Replies
with short upstream TTLs below `CACHE_MIN_TTL` bypass storage to avoid extending
their lifetime through the cache component's minimum clamp. EDNS/DNSSEC requests
and complex answers bypass the address cache. This is an IPv4 UDP listener;
client TCP transport, feed scheduling/reloading, and final evaluation remain
outside this change.

Run the core tests with `python -m pytest tests/test_proxy.py -q`. They use
injected components and include real concurrent loopback UDP requests.

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
