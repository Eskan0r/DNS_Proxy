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
# TODO: import sqlite3, matplotlib, argparse, time


def run_evaluation(proxy_host: str = "127.0.0.1", proxy_port: int = 5353,
                   benign_file: str = "data/benign500.txt",
                   malicious_file: str = "data/malicious500.txt") -> dict:
    """TODO: send 1000 queries, collect decisions, compute:
    returns {'block_rate':..,'fp':..,'fn':..,'avg_latency_ms':.., 'direct_avg_ms':..}
    """
    raise NotImplementedError


def generate_charts(db_path: str, out_dir: str) -> None:
    """TODO: query logger DB, save blocked_by_category.png + decisions.png."""
    raise NotImplementedError


if __name__ == "__main__":
    # TODO: argparse --db --out, call generate_charts + print stats
    raise NotImplementedError
