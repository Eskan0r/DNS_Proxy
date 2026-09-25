"""
Run: python main.py --port 5353 (dev) / --port 53 (prod, needs admin)
"""
# TODO: argparse --ip --port, init DNSProxy, serve_forever()
import argparse

def main():
    parser = argparse.ArgumentParser(description="Lightweight DNS Security Proxy")
    parser.add_argument("--ip", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5353)
    args = parser.parse_args()
    # TODO: from src.proxy import DNSProxy; DNSProxy(args.ip, args.port).serve_forever()
    raise NotImplementedError

if __name__ == "__main__":
    main()
