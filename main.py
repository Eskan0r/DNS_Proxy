"""Command-line entry point for the DNS security proxy."""
import argparse
import logging

from src import config
from src.proxy import DNSProxy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lightweight DNS Security Proxy")
    parser.add_argument("--ip", default=config.LISTEN_IP)
    parser.add_argument("--port", type=int, default=config.LISTEN_PORT_TEST)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        DNSProxy(args.ip, args.port).serve_forever()
    except KeyboardInterrupt:
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        logging.error("Could not run proxy: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
