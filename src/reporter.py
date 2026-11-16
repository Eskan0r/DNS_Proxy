"""Report generator + final eval, Kareem Saleh

Contract:
    python -m src.reporter --db logs/dns_proxy.db --out report/
    Reads Vinh's SQLite, makes blocked/allowed charts, prints:
      block rate, FP/FN, avg latency (proxy vs direct).

Requirements:
- Final eval: 500 benign (Tranco) + 500 malicious (feeds) through proxy.
- Charts: matplotlib bar/pie (blocked by category, allow vs block).
- Also owns README run instructions.
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


def generate_charts(db_path: str, out_dir: str) -> None:
    """Save decision and blocked-category charts, including empty databases."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT decision, COUNT(*) FROM queries GROUP BY decision"
    ).fetchall()
    decisions = dict(rows)

    rows = conn.execute(
        "SELECT category, COUNT(*) FROM queries WHERE decision = 'block' GROUP BY category"
    ).fetchall()
    conn.close()

    categories = {}
    for category, count in rows:
        name = category.split(":")[0]
        categories[name] = categories.get(name, 0) + count

    os.makedirs(out_dir, exist_ok=True)

    plt.figure()
    if decisions:
        plt.pie(decisions.values(), labels=decisions.keys(), autopct="%1.0f%%")
    else:
        plt.text(0.5, 0.5, "No queries logged", ha="center")
    plt.title("Query decisions")
    plt.savefig(os.path.join(out_dir, "decisions.png"), bbox_inches="tight")
    plt.close()

    plt.figure()
    bars = plt.bar(list(categories.keys()), list(categories.values()))
    plt.bar_label(bars)
    plt.gca().yaxis.get_major_locator().set_params(integer=True)
    plt.title("Blocked queries by category")
    plt.ylabel("Blocked queries")
    plt.savefig(os.path.join(out_dir, "blocked_by_category.png"), bbox_inches="tight")  # save the picture
    plt.close()


def generate_eval_charts(results: dict, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)

    if results['tp'] + results['fn'] > 0:
        plt.figure()
        plt.pie([results['tp'], results['fn']],
                labels=["Blocked (TP)", "Missed (FN)"], autopct="%1.0f%%")
        plt.title("Malicious domains")
        plt.savefig(os.path.join(out_dir, "malicious_results.png"), bbox_inches="tight")
        plt.close()
    else:
        print("No malicious results to chart")

    if results['tn'] + results['fp'] > 0:
        plt.figure()
        plt.pie([results['tn'], results['fp']],
                labels=["Allowed (TN)", "Blocked (FP)"], autopct="%1.0f%%")
        plt.title("Benign domains")
        plt.savefig(os.path.join(out_dir, "benign_results.png"), bbox_inches="tight")
        plt.close()
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
