"""Report generator + final eval, Kareem Saleh

Makes the charts from the log database and from the evaluation results.
Run: python -m src.reporter --evaluate --db logs/dns_proxy.db --out report/
"""
import sqlite3
import json
from pathlib import Path
import argparse
import time
import os
import matplotlib
matplotlib.use("Agg")  # File output also works on machines without a desktop/Tk.
import matplotlib.pyplot as plt
from dnslib import DNSRecord, QTYPE, RCODE
from . import config

# same meaning gets the same color in every chart
GREEN = "#2e9e5b"
RED = "#d64545"
ORANGE = "#f28c28"
BLUE = "#4a7fb5"
GRAY = "#8c8c8c"

DECISION_COLORS = {"allow": GREEN, "block": RED, "cache": BLUE, "error": GRAY}
DECISION_NAMES = {"allow": "Allowed", "block": "Blocked", "cache": "Cache", "error": "Error"}

FIG_SIZE = (7, 5)
DPI = 200


def run_evaluation(proxy_host: str = "127.0.0.1", proxy_port: int = 5353,
                   benign_file: str = str(config.DATA_DIR / "benign500.txt"),
                   malicious_file: str = str(config.DATA_DIR / "malicious500.txt"), *,
                   direct_host: str = "8.8.8.8", direct_port: int = 53,
                   timeout: float = 7.0) -> dict:
    """Measure answered samples; report failures and coverage separately.

    NOERROR/NXDOMAIN with no address is a valid nonblocked response. SERVFAIL,
    REFUSED, truncation, malformed replies, and timeouts are evaluation errors.
    No answers means undefined rates/latency, represented by None, not zero.
    """
    def load(path):
        return [name for line in Path(path).read_text(encoding="utf-8-sig").splitlines()
                if (name := line.split("#", 1)[0].strip())]

    def query(domain, host, port):
        question = DNSRecord.question(domain)
        start = time.perf_counter()
        wire = question.send(host, port, timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000
        reply = DNSRecord.parse(wire)
        if (not reply.header.qr or reply.header.id != question.header.id
                or reply.questions != question.questions or reply.header.tc
                or reply.header.rcode not in (RCODE.NOERROR, RCODE.NXDOMAIN)):
            raise ValueError("Invalid or unsuccessful DNS response")
        blocked = any(rr.rtype == QTYPE.A and str(rr.rdata) == config.SINKHOLE_IPV4
                      for rr in reply.rr)
        return blocked, elapsed

    benign, malicious = load(benign_file), load(malicious_file)
    counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0,
              "benign_errors": 0, "malicious_errors": 0, "direct_errors": 0}
    latencies, direct_latencies = [], []
    for names, is_bad in ((benign, False), (malicious, True)):
        for domain in names:
            try:
                blocked, elapsed = query(domain, proxy_host, proxy_port)
            except Exception:
                counts["malicious_errors" if is_bad else "benign_errors"] += 1
                continue
            latencies.append(elapsed)
            key = ("tp" if blocked else "fn") if is_bad else ("fp" if blocked else "tn")
            counts[key] += 1
    for domain in benign:
        try:
            _, elapsed = query(domain, direct_host, direct_port)
            direct_latencies.append(elapsed)
        except Exception:
            counts["direct_errors"] += 1

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None

    benign_answered = counts["tn"] + counts["fp"]
    malicious_answered = counts["tp"] + counts["fn"]
    return dict(counts,
                errors=counts["benign_errors"] + counts["malicious_errors"],
                benign_total=len(benign), malicious_total=len(malicious),
                benign_answered=benign_answered, malicious_answered=malicious_answered,
                benign_coverage=ratio(benign_answered, len(benign)),
                malicious_coverage=ratio(malicious_answered, len(malicious)),
                block_rate=ratio(counts["tp"], malicious_answered),
                fp_rate=ratio(counts["fp"], benign_answered),
                fn_rate=ratio(counts["fn"], malicious_answered),
                avg_latency_ms=ratio(sum(latencies), len(latencies)),
                direct_avg_ms=ratio(sum(direct_latencies), len(direct_latencies)))


def draw_pie(values, labels, colors, title, total, path):
    """Draw one pie chart and save it to path."""
    # skip slices that are 0 so the labels do not overlap
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
            wedgeprops={"edgecolor": "white", "linewidth": 1})
    plt.title(title + " (n=" + str(total) + ")")
    plt.savefig(path, dpi=DPI, bbox_inches="tight")
    plt.close()


def draw_empty(title, message, path):
    """Save a simple chart that only shows a message."""
    # still write a picture when there is no data, so the png file always exists
    plt.figure(figsize=FIG_SIZE)
    plt.text(0.5, 0.5, message, ha="center", va="center", fontsize=14, color=GRAY)
    plt.axis("off")
    plt.title(title)
    plt.savefig(path, dpi=DPI, bbox_inches="tight")
    plt.close()


def generate_charts(db_path: str, out_dir: str) -> None:
    """Save decision and blocked-category charts, including empty databases."""
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

    decisions_path = os.path.join(out_dir, "decisions.png")
    if decisions:
        values = []
        labels = []
        colors = []
        for name in decisions:
            values.append(decisions[name])
            labels.append(DECISION_NAMES.get(name, name))
            colors.append(DECISION_COLORS.get(name, GRAY))
        draw_pie(values, labels, colors, "DNS Decisions", sum(values), decisions_path)
    else:
        draw_empty("DNS Decisions", "No queries logged", decisions_path)

    category_path = os.path.join(out_dir, "blocked_by_category.png")
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
        plt.savefig(category_path, dpi=DPI, bbox_inches="tight")
        plt.close()
    else:
        draw_empty("Blocked Queries by Category", "No blocked queries", category_path)


def generate_eval_charts(results: dict, out_dir: str) -> None:
    """Save malicious_results.png and benign_results.png from the eval results."""
    os.makedirs(out_dir, exist_ok=True)

    malicious_total = results['tp'] + results['fn']
    if malicious_total > 0:
        draw_pie([results['tp'], results['fn']],
                 ["Blocked (TP)", "Missed (FN)"], [RED, ORANGE],
                 "Malicious Domains", malicious_total,
                 os.path.join(out_dir, "malicious_results.png"))
    else:
        print("No malicious results to chart")

    benign_total = results['tn'] + results['fp']
    if benign_total > 0:
        draw_pie([results['tn'], results['fp']],
                 ["Allowed (TN)", "Blocked (FP)"], [GREEN, RED],
                 "Benign Domains", benign_total,
                 os.path.join(out_dir, "benign_results.png"))
    else:
        print("No benign results to chart")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate query charts; optionally run evaluation")
    parser.add_argument("--db", default=str(config.DB_PATH))
    parser.add_argument("--out", default="report/")
    parser.add_argument("--evaluate", action="store_true")
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=5353)
    parser.add_argument("--benign", default=str(config.DATA_DIR / "benign500.txt"))
    parser.add_argument("--malicious", default=str(config.DATA_DIR / "malicious500.txt"))
    args = parser.parse_args(argv)
    if args.evaluate:
        results = run_evaluation(args.proxy_host, args.proxy_port, args.benign, args.malicious)
        Path(args.out).mkdir(parents=True, exist_ok=True)
        (Path(args.out) / "evaluation.json").write_text(json.dumps(results, indent=2) + "\n")
        generate_eval_charts(results, args.out)
        print(json.dumps(results, indent=2))
    generate_charts(args.db, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
