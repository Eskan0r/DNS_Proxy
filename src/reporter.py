"""Report generator + final eval, Kareem Saleh

Sends 500 benign + 500 malicious domains through the proxy, then makes
charts from the log database and from the results.

HOW TO LINK AND RUN
What this needs from the other files:
  - proxy running on 127.0.0.1:5353, answers 0.0.0.0 for blocked domains
  - proxy logs through QueryLogger into logs/dns_proxy.db
    (queries table: ts, client_ip, domain, qtype, decision, category, latency_ms)
  - data/benign500.txt and data/malicious500.txt

Steps:
  1. delete the old logs/dns_proxy.db
  2. start the proxy: python main.py --port 5353 (restart it every run so the cache is empty)
  3. in a second terminal: python -m src.reporter --db logs/dns_proxy.db --out report/
If the proxy uses another port, change proxy_port in the run_evaluation call.
quick demo: add --limit 50 to only send 50 + 50 domains

Output: PNG charts in report/ and the metrics printed in the terminal.
"""
import sqlite3
import argparse
import time
import os
import matplotlib.pyplot as plt
from dnslib import DNSRecord

GREEN = "#2e9e5b"
RED = "#d64545"
ORANGE = "#f28c28"
BLUE = "#4a7fb5"
GRAY = "#8c8c8c"
EDGE = "white"

DECISION_COLORS = {"allow": GREEN, "block": RED, "cache": BLUE, "error": GRAY}
DECISION_NAMES = {"allow": "Allowed", "block": "Blocked", "cache": "Cache", "error": "Error"}

FIG_SIZE = (7, 5)
DPI = 200


def run_evaluation(proxy_host: str = "127.0.0.1", proxy_port: int = 5353,
                   benign_file: str = "data/benign500.txt",
                   malicious_file: str = "data/malicious500.txt",
                   limit: int = None) -> dict:
    """Send the benign and malicious domains to the proxy and return a dict with
    keys: block_rate, tp, tn, fp, fn, fp_rate, fn_rate, errors,
    avg_latency_ms, direct_avg_ms.
    """
    benign = []
    with open(benign_file) as f:
        for line in f:
            domain = line.strip()
            if domain:
                benign.append(domain)

    malicious = []
    with open(malicious_file) as f:
        for line in f:
            domain = line.strip()
            if domain:
                malicious.append(domain)

    if limit:
        benign = benign[:limit]
        malicious = malicious[:limit]

    errors = 0

    fp = 0
    latencies = []
    for domain in benign:
        try:
            question = DNSRecord.question(domain)
            start = time.time()
            # timeout is 2 so a slow domain doesn't hold up the run
            reply_bytes = question.send(proxy_host, proxy_port, timeout=2)
            elapsed_ms = (time.time() - start) * 1000
            reply = DNSRecord.parse(reply_bytes)
            ip = str(reply.rr[0].rdata)
        except Exception:
            errors = errors + 1
            continue
        latencies.append(elapsed_ms)
        # the proxy answers 0.0.0.0 when it blocks a domain, so 0.0.0.0 means blocked
        if ip == "0.0.0.0":
            fp = fp + 1

    fn = 0
    malicious_answered = 0
    for domain in malicious:
        try:
            question = DNSRecord.question(domain)
            reply_bytes = question.send(proxy_host, proxy_port, timeout=2)
            reply = DNSRecord.parse(reply_bytes)
            ip = str(reply.rr[0].rdata)
        except Exception:
            errors = errors + 1
            continue
        malicious_answered = malicious_answered + 1
        if ip != "0.0.0.0":
            fn = fn + 1

    direct_latencies = []
    for domain in benign:
        try:
            question = DNSRecord.question(domain)
            start = time.time()
            question.send("8.8.8.8", 53, timeout=2)
            elapsed_ms = (time.time() - start) * 1000
        except Exception:
            continue
        direct_latencies.append(elapsed_ms)

    benign_answered = len(latencies)

    avg_latency_ms = sum(latencies) / len(latencies) if latencies else 0.0
    direct_avg_ms = sum(direct_latencies) / len(direct_latencies) if direct_latencies else 0.0

    blocked_bad = malicious_answered - fn
    block_rate = blocked_bad / malicious_answered if malicious_answered else 0.0
    fp_rate = fp / benign_answered if benign_answered else 0.0
    fn_rate = fn / malicious_answered if malicious_answered else 0.0

    return {
        'block_rate': block_rate,
        'fp': fp,
        'fn': fn,
        'tp': malicious_answered - fn,
        'tn': benign_answered - fp,
        'fp_rate': fp_rate,
        'fn_rate': fn_rate,
        'errors': errors,
        'avg_latency_ms': avg_latency_ms,
        'direct_avg_ms': direct_avg_ms,
    }


def draw_pie(values, labels, colors, title, total, path):
    """Draw one pie chart and save it to path (skips slices that are 0)."""
    keep_values = []
    keep_labels = []
    keep_colors = []
    for i in range(len(values)):
        if values[i] > 0:
            keep_values.append(values[i])
            keep_labels.append(labels[i] + ": " + str(values[i]))
            keep_colors.append(colors[i])

    plt.figure(figsize=FIG_SIZE)
    plt.pie(keep_values, labels=keep_labels, colors=keep_colors,
            autopct="%1.1f%%", startangle=90,
            wedgeprops={"edgecolor": EDGE, "linewidth": 1})
    plt.title(title + " (n=" + str(total) + ")")
    plt.savefig(path, dpi=DPI, bbox_inches="tight")
    plt.close()


def generate_charts(db_path: str, out_dir: str) -> None:
    """Read the log database and save decisions.png and blocked_by_category.png."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT decision, COUNT(*) FROM queries GROUP BY decision"
    ).fetchall()
    # decision can be "block" or "block:reason", so only keep the part before the colon
    decisions = {}
    for decision, count in rows:
        name = (decision or "unknown").split(":")[0]
        decisions[name] = decisions.get(name, 0) + count

    rows = conn.execute(
        "SELECT category, COUNT(*) FROM queries WHERE decision LIKE 'block%' GROUP BY category"
    ).fetchall()
    conn.close()

    # category looks like "blocklist:bad.com", keep just the first part
    categories = {}
    for category, count in rows:
        name = (category or "unknown").split(":")[0]
        categories[name] = categories.get(name, 0) + count

    os.makedirs(out_dir, exist_ok=True)

    if decisions:
        names = list(decisions.keys())
        values = list(decisions.values())
        labels = []
        colors = []
        for name in names:
            labels.append(DECISION_NAMES.get(name, str(name)))
            colors.append(DECISION_COLORS.get(name, GRAY))
        draw_pie(values, labels, colors, "DNS Decisions", sum(values),
                 os.path.join(out_dir, "decisions.png"))
    else:
        print("No queries in the database to chart")

    if categories:
        names = list(categories.keys())
        values = list(categories.values())

        plt.figure(figsize=FIG_SIZE)
        bars = plt.bar(names, values, color=RED)
        plt.bar_label(bars)
        plt.title("Blocked Queries by Category (n=" + str(sum(values)) + ")")
        plt.xlabel("Category")
        plt.ylabel("Blocked queries")
        plt.gca().yaxis.get_major_locator().set_params(integer=True)
        plt.gca().spines["top"].set_visible(False)
        plt.gca().spines["right"].set_visible(False)
        plt.grid(axis="y", color="#dddddd")
        plt.gca().set_axisbelow(True)
        if len(names) > 5:
            plt.xticks(rotation=45, ha="right")
        plt.savefig(os.path.join(out_dir, "blocked_by_category.png"), dpi=DPI, bbox_inches="tight")
        plt.close()
    else:
        print("No blocked queries to chart")


def generate_eval_charts(results: dict, out_dir: str) -> None:
    """Save malicious_results.png and benign_results.png from the eval results."""
    os.makedirs(out_dir, exist_ok=True)

    malicious_total = results['tp'] + results['fn']
    if malicious_total > 0:
        draw_pie([results['tp'], results['fn']],
                 ["Blocked (TP)", "Missed (FN)"],
                 [RED, ORANGE],
                 "Malicious Domains", malicious_total,
                 os.path.join(out_dir, "malicious_results.png"))
    else:
        print("No malicious results to chart")

    benign_total = results['tn'] + results['fp']
    if benign_total > 0:
        draw_pie([results['tn'], results['fp']],
                 ["Allowed (TN)", "Blocked (FP)"],
                 [GREEN, RED],
                 "Benign Domains", benign_total,
                 os.path.join(out_dir, "benign_results.png"))
    else:
        print("No benign results to chart")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="logs/dns_proxy.db")
    parser.add_argument("--out", default="report/")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    # run the queries first so the proxy logs them before we chart the database
    results = run_evaluation(limit=args.limit)
    print("Block rate:", results['block_rate'])
    print("True positives:", results['tp'])
    print("True negatives:", results['tn'])
    print("False positives:", results['fp'])
    print("False negatives:", results['fn'])
    print("False positive rate:", results['fp_rate'])
    print("False negative rate:", results['fn_rate'])
    print("Errors:", results['errors'])
    print("Avg latency (proxy) ms:", results['avg_latency_ms'])
    print("Avg latency (direct) ms:", results['direct_avg_ms'])
    generate_charts(args.db, args.out)
    generate_eval_charts(results, args.out)
