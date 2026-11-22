"""Readable demo commands using the real proxy and isolated local demo data."""
import argparse
from contextlib import closing
import json
import logging
import os
from pathlib import Path
import shutil
import socket
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def demo_dir():
    directory = ROOT / '.demo'
    if directory.is_symlink() or directory.resolve().parent != ROOT.resolve():
        raise RuntimeError('The demo directory must be a real directory inside DNS_Proxy.')
    return directory


def prepare():
    directory = demo_dir()
    data = directory / 'data'
    data.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / 'data/top200.txt', data / 'top200.txt')
    for name in ('blocklist.txt', 'allowlist.txt'):
        path = data / name
        if not path.exists():
            path.write_text('', encoding='utf-8')
    return directory


def server_info():
    try:
        return json.loads((demo_dir() / 'server.json').read_text(encoding='utf-8'))
    except FileNotFoundError:
        return None


def control(info, action):
    """Only control the demo instance identified by its random session token."""
    with socket.create_connection(('127.0.0.1', info['control_port']), timeout=2) as sock:
        sock.settimeout(2)
        request = json.dumps({'token': info['token'], 'action': action}) + '\n'
        sock.sendall(request.encode())
        with sock.makefile('r') as reader:
            response = json.loads(reader.readline(4096))
    return response.get('ok') is True


def running_server():
    info = server_info()
    if info is not None:
        try:
            if control(info, 'ping'):
                return info
        except (OSError, ValueError):
            pass
    return None


def start(port):
    from src import config
    from src.proxy import DNSProxy

    if running_server():
        raise RuntimeError('The demo is already running. Use its existing terminal, or npm run reset.')
    # Bind errors are explained before constructing the database or workers.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.bind(('127.0.0.1', port))
        except OSError as exc:
            raise RuntimeError(
                f'Port {port} is unavailable. Stop the previous proxy with Ctrl+C, '
                f'or use npm start -- --port 15353. ({exc})') from None
    directory = prepare()
    config.DATA_DIR = directory / 'data'
    config.DB_PATH = directory / 'dns_proxy.db'
    proxy = DNSProxy('127.0.0.1', port)
    # Recording uses editable demo policies; configured production feeds stay separate.
    proxy._maintenance.updater.feeds = {}
    token = uuid.uuid4().hex

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                request = json.loads(self.rfile.readline(4096))
                valid = request.get('token') == token
                action = request.get('action')
                ok = valid and action in ('ping', 'stop')
                if ok and action == 'stop':
                    proxy.shutdown()
                self.wfile.write((json.dumps({'ok': ok}) + '\n').encode())
            except (OSError, ValueError):
                return

    class ControlServer(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with ControlServer(('127.0.0.1', 0), Handler) as controller:
        thread = threading.Thread(target=controller.serve_forever,
                                  kwargs={'poll_interval': 0.1}, name='demo-control')
        thread.start()
        info_path = directory / 'server.json'
        pending = info_path.with_suffix('.tmp')
        pending.write_text(json.dumps({'port': port, 'token': token,
                                      'control_port': controller.server_address[1]}), encoding='utf-8')
        pending.replace(info_path)
        print(f'\nDNS PROXY DEMO  |  127.0.0.1:{port}')
        print('Real upstream DNS. Demo policies, logs, and charts stay in .demo/.')
        print('Use a second terminal for npm run google, npm run example, and the other steps.')
        print('Ctrl+C stops the server. npm run reset stops it and clears this demo.\n')
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        try:
            proxy.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            proxy.close()
            controller.shutdown()
            thread.join()
            info_path.unlink(missing_ok=True)
            print('\nDemo stopped.')


def query(domain, qtype='A'):
    from dnslib import DNSRecord, RCODE

    info = running_server()
    if info is None:
        raise RuntimeError('The demo is not running. Run npm start in another terminal first.')
    question = DNSRecord.question(domain, qtype)
    started = time.perf_counter()
    reply = DNSRecord.parse(question.send('127.0.0.1', info['port'], timeout=10))
    elapsed = (time.perf_counter() - started) * 1000
    if (not reply.header.qr or reply.header.id != question.header.id
            or reply.questions != question.questions):
        raise RuntimeError('The DNS reply did not match the request.')
    with closing(sqlite3.connect(demo_dir() / 'dns_proxy.db')) as connection:
        event = connection.execute(
            'SELECT decision, category FROM queries WHERE domain = ? AND qtype = ? '
            'ORDER BY rowid DESC LIMIT 1', (domain.lower().rstrip('.'), qtype)).fetchone()
    decision, reason = event or ('unknown', 'No matching log entry')
    if reply.header.rcode == RCODE.NXDOMAIN:
        status = 'NOT FOUND (NXDOMAIN)'
    elif reply.header.rcode != RCODE.NOERROR:
        status = RCODE[reply.header.rcode]
    else:
        status = {'allow': 'ALLOWED', 'block': 'BLOCKED', 'cache': 'ALLOWED - CACHE HIT'}.get(
            decision, decision.upper())
    print(f'\n{domain}  {qtype}')
    print(f'  Result   {status}')
    print(f'  Reason   {reason}')
    print(f'  Time     {elapsed:.2f} ms')
    if reply.rr:
        for rr in reply.rr:
            print(f'  Answer   {rr.rdata}  (TTL {rr.ttl}s)')
    else:
        print('  Answer   No address records')
    print()
    return 0 if reply.header.rcode in (RCODE.NOERROR, RCODE.NXDOMAIN) else 1


def update_policy(kind):
    directory = prepare()
    path = directory / 'data' / f'{kind}.txt'
    entries = path.read_text(encoding='utf-8').splitlines()
    if 'example.com' not in entries:
        entries.append('example.com')
    path.write_text('\n'.join(entries) + '\n', encoding='utf-8')
    if kind == 'blocklist':
        allow = directory / 'data/allowlist.txt'
        entries = [line for line in allow.read_text(encoding='utf-8').splitlines()
                   if line.strip().lower().rstrip('.') != 'example.com']
        allow.write_text('\n'.join(entries) + ('\n' if entries else ''), encoding='utf-8')
        print('\nAdded example.com to the demo blocklist and removed its allowlist override.')
        print('After reload, example.com and its subdomains will be blocked.')
    else:
        print('\nAdded example.com to the demo allowlist.')
        print('After reload, the exact hostname example.com will be allowed again.')
    if running_server():
        print('Wait 65 seconds, then run npm run example.\n')
    else:
        print('Run npm start to load this policy.\n')


def display():
    path = demo_dir() / 'dns_proxy.db'
    if not path.exists():
        print('No demo requests yet. Run npm start, then npm run google.')
        return
    with closing(sqlite3.connect(path)) as connection:
        rows = connection.execute(
            'SELECT domain, qtype, decision, category, latency_ms '
            'FROM queries ORDER BY rowid DESC LIMIT 20').fetchall()
        counts = dict(connection.execute('SELECT decision, COUNT(*) FROM queries GROUP BY decision'))
    print('\nDEMO REQUEST LOG  |  newest first\n')
    print(f'{"DOMAIN":<30} {"TYPE":<5} {"DECISION":<8} {"TIME":>9}  REASON')
    print('-' * 90)
    for domain, qtype, decision, reason, latency in rows:
        print(f'{domain:<30} {qtype:<5} {decision.upper():<8} {latency:>6.2f} ms  {reason}')
    print(f'\nAllowed: {counts.get("allow", 0)}  Cached: {counts.get("cache", 0)}  '
          f'Blocked: {counts.get("block", 0)}  Errors: {counts.get("error", 0)}\n')


def charts(open_images=True):
    from src.reporter import generate_charts

    directory = demo_dir()
    if not (directory / 'dns_proxy.db').exists():
        raise RuntimeError('No demo database yet. Run npm start and send a few queries first.')
    output = directory / 'report'
    generate_charts(str(directory / 'dns_proxy.db'), str(output))
    for name in ('decisions.png', 'blocked_by_category.png'):
        path = (output / name).resolve()
        print(f'Created .demo/report/{name}')
        if open_images:
            if sys.platform == 'win32':
                os.startfile(str(path))
            else:
                subprocess.Popen(['open' if sys.platform == 'darwin' else 'xdg-open', str(path)])


def reset():
    info = running_server()
    if info is not None:
        if not control(info, 'stop'):
            raise RuntimeError('Could not stop the demo. Press Ctrl+C in its terminal, then retry.')
        deadline = time.monotonic() + 15
        while server_info() is not None and time.monotonic() < deadline:
            time.sleep(0.1)
        if server_info() is not None:
            raise RuntimeError('The demo is still stopping. Retry reset after its terminal exits.')
    directory = demo_dir()  # Resolves and verifies the fixed workspace target before deletion.
    if directory.exists():
        shutil.rmtree(directory)
    prepare()
    print('\nDemo reset. Policies, cache, request history, and charts are cleared.')
    print('Your production data/, logs/, and report/ files were preserved.')
    print('Run npm start for a fresh recording.\n')


def run_tests(arguments):
    parent = ROOT / '.venv'
    parent.mkdir(exist_ok=True)
    directory = tempfile.mkdtemp(prefix='pytest-demo-', dir=parent)
    return subprocess.call([sys.executable, '-m', 'pytest', '-q', '-rs',
                            '-p', 'no:cacheprovider', '--basetemp', directory,
                            *(arguments or ['tests'])], cwd=ROOT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action')
    parser.add_argument('--port', type=int, default=5300)
    parser.add_argument('--no-open', action='store_true')
    args, extra = parser.parse_known_args()
    if extra and args.action != 'test':
        parser.error('Unrecognized arguments: ' + ' '.join(extra))
    queries = {'google': ('google.com', 'A'), 'example': ('example.com', 'A'),
               'ipv6': ('example.com', 'AAAA'), 'typosquat': ('gooogle.com', 'A'),
               'dga': ('zx9f3kq7m2v8c1.com', 'A'), 'nondomain': ('does-not-exist.invalid', 'A')}
    try:
        if args.action in queries:
            return query(*queries[args.action])
        if args.action == 'start':
            if not 1 <= args.port <= 65535:
                raise RuntimeError('The port must be between 1 and 65535.')
            start(args.port)
        elif args.action in ('blocklist', 'allowlist'):
            update_policy(args.action)
        elif args.action == 'display':
            display()
        elif args.action == 'charts':
            charts(not args.no_open)
        elif args.action == 'reset':
            reset()
        elif args.action == 'test':
            return run_tests(extra)
        elif args.action == 'help':
            print('''
DNS PROXY DEMO

  npm run setup       Install Python dependencies (once)
  npm start           Start the demo on port 5300 (terminal 1)
  npm run google      Resolve google.com; repeat to show caching
  npm run example     Resolve example.com
  npm run ipv6        Resolve example.com with AAAA
  npm run typosquat   Block a lookalike name
  npm run dga         Block a high-entropy name
  npm run blocklist   Block example.com; wait 65s, then run example
  npm run allowlist   Allow example.com; wait 65s, then run example
  npm run nondomain   Show NXDOMAIN for a nonexistent name
  npm run display     Show recent decisions and counts
  npm run charts      Generate and open charts
  npm test            Run tests with a fresh temporary directory
  npm run reset       Stop this demo and clear its data for a new run

Policies reload every 60 seconds. Only .demo/ is changed by the demo commands.
''')
        else:
            raise RuntimeError(f'Unknown demo command: {args.action}. Run npm run help.')
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
        print(f'\nDemo: {exc}\n', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
