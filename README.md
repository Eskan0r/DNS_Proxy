Our team will build a lightweight DNS server designed to inspect outbound domain requests on a local network, as well as identify malicious traffic and intercept threats before connections are established.

Instead of allowing client devices to resolve IP addresses directly through public providers, all network devices will route their DNS traffic through our server. Our system will evaluate incoming queries in layers: 1, threat intel blocklist (URLhaus, PhishTank, Malware Domain List) and local allowlist, 2, heuristic checks for entropy/DGA like names, typosquatting, and newly observed/ short TTL domains. If a query is determined to be safe, the server resolves it normally. If it matches malicious criteria, the server will sinkhole the request and log it.

All decisions are logged to a SQLite/JSON (timestamp, client IP, domain, decision, category) for reporting and evaluation. We will evaluate based on benign (Tranco top list) vs. malicious samples, measuring block rate, false positive/negative rate, and latency overhead vs. direct resolution.

Task Delegation
Toan Nguyen: Upstream asker, forwards safe domains to google/cloudflare and returns the real IP, implements DoH, timeout/retries + fallback, and measures latency overhead.
Minkyu Jeong: Cache helper, saves past answers with expiration time and checks them first, enforces real TTL expiry, LRU eviction when full, tests hit rate/speed.
Artin Seyrafi: Block responder, returns dead IP and the threat feed updater that downloads bad domains daily, clean/normalize feeds and maintain allowlist override to avoid false positives.
Justin Truong: Banned list checker (input name string, output blocked/clean), handle subdomains (a.bad.com is part of bad.com), and make lookup efficient for 100k+ domains with speed test.
Megan Tran: Lookalike checker, essentially a typosquatting checker like paypa1.com vs paypal.com, build top 200 real list, implement edit distance, tune threshold with FP test.
Chaiyun Suhr: Gibberish checker for random DGA-like names using length and entropy score, pick threshold and evaluate on benign (Tranco) vs malicious samples.
Vinh Nguyen: Logger that saves every request, decision, and reason to SQLite (you can do MySQL or Postgres or whatever u want, but I recommend SQLite), plus design schema and provide query functions like get_top_blocked() for report generator.
Kareem Saleh: Report generator with blocked/allowed charts plus README and run instructions, run final evaluation (500 benign + 500 bad) to report block rate, FP/FN, and avg latency.
Ronak Chavva: Implement core DNS proxy engine (UDP listener, DNS wire format parsing, threaded request handling, TTL-aware cache lookup, upstream DoH forwarding, and sinkhole enforcement), plus integration for everyone else.
