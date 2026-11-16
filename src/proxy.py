"""Threaded UDP DNS engine with injectable security and storage components.

Policy precedes the cache. Raw upstream forwarding preserves DNS errors,
CNAME chains, authority records, and non-address questions. Only simple
IN A/AAAA replies are reconstructed from the address cache.
"""
from concurrent.futures import ThreadPoolExecutor
from importlib import import_module
import logging
import socket
import threading
import time

from dnslib import A, AAAA, CLASS, DNSHeader, DNSRecord, OPCODE, QTYPE, RCODE, RR

from . import config
from .utils import normalize_domain

LOG = logging.getLogger(__name__)


class _SerialLogger:
    """Keep the SQLite connection and its operations on one dedicated thread."""

    def __init__(self):
        from .logger import QueryLogger
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="dns-log")
        try:
            self._logger = self._pool.submit(QueryLogger, str(config.DB_PATH)).result()
        except Exception:
            self._pool.shutdown()
            raise

    def log(self, **event):
        self._pool.submit(self._logger.log, **event).result()

    def close(self):
        def close_connection():
            if hasattr(self._logger, "close"):
                self._logger.close()
            else:
                self._logger.connection.close()
        try:
            self._pool.submit(close_connection).result()
        finally:
            self._pool.shutdown()


class DNSProxy:
    """A single-use IPv4 UDP server. Injected components are caller-owned.

    Defaults require the component branches and data files to be integrated.
    Missing implementations fail at startup instead of bypassing security.
    Port zero is supported for local tests.
    """

    def __init__(self, ip: str = config.LISTEN_IP,
                 port: int = config.LISTEN_PORT_TEST, *, cache=None,
                 blocklist=None, allowlist=None, typosquat=None, dga=None,
                 upstream=None, logger=None, max_workers: int = 20):
        if not 0 <= port <= 65535 or max_workers < 1:
            raise ValueError("Invalid port or worker count")
        self.ip, self.port = ip, port
        self.max_workers = max_workers
        self._stop = threading.Event()
        self._socket = None
        self._owned = []
        self._closed = False
        try:
            self.cache = self._component(cache, "cache", "DNSCache")
            self.blocklist = self._component(blocklist, "blocklist", "BlocklistChecker")
            self.allowlist = self._component(allowlist, "feeds", "Allowlist")
            self.typosquat = self._component(typosquat, "typosquat", "TyposquatChecker")
            self.dga = self._component(dga, "dga", "DGADetector")
            if blocklist is None and (config.DATA_DIR / "blocklist.txt").exists():
                self.blocklist.load_file(str(config.DATA_DIR / "blocklist.txt"))
            if typosquat is None:
                self.typosquat.load_top_file(str(config.DATA_DIR / "top200.txt"))
            self.upstream = self._component(upstream, "upstream", "UpstreamResolver")
            self.logger = logger if logger is not None else _SerialLogger()
            if logger is None:
                self._owned.append(self.logger)
        except Exception as exc:
            self.close()
            raise RuntimeError(
                f"Component initialization failed: {type(exc).__name__}: {exc}. "
                "Integrate the component branches and configure their data files first."
            ) from exc

    def _component(self, supplied, module, name):
        if supplied is not None:
            return supplied
        try:
            component = getattr(import_module(f".{module}", __package__), name)()
        except NotImplementedError as exc:
            raise RuntimeError(f"src.{module}.{name} is still a stub") from exc
        self._owned.append(component)
        return component

    def serve_forever(self) -> None:
        """Bind UDP, bound pending work, and drain workers before cleanup."""
        if self._closed or self._socket is not None:
            raise RuntimeError("Proxy is closed or already serving")
        slots = threading.BoundedSemaphore(self.max_workers * 2)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                self._socket = sock
                sock.bind((self.ip, self.port))
                self.port = sock.getsockname()[1]
                sock.settimeout(0.2)
                LOG.info("DNS proxy listening on %s:%s", self.ip, self.port)
                with ThreadPoolExecutor(max_workers=self.max_workers,
                                        thread_name_prefix="dns-query") as pool:
                    while not self._stop.is_set():
                        if not slots.acquire(timeout=0.2):
                            continue
                        try:
                            data, client = sock.recvfrom(65535)
                        except socket.timeout:
                            slots.release()
                            continue
                        except OSError:
                            slots.release()
                            raise
                        try:
                            pool.submit(self._send_query, sock, data, client, slots)
                        except Exception:
                            slots.release()
                            raise
        finally:
            self._socket = None
            self.close()

    def shutdown(self) -> None:
        """Request shutdown; the listener timeout wakes the receive loop."""
        self._stop.set()

    def close(self) -> None:
        """Release owned components once the server's workers have drained."""
        if self._socket is not None:
            self.shutdown()
            return
        if self._closed:
            return
        self._closed = True
        for component in reversed(self._owned):
            close = getattr(component, "close", None)
            if close:
                try:
                    close()
                except Exception:
                    LOG.exception("Component cleanup failed")

    def _send_query(self, sock, data, client, slots):
        try:
            reply = self.handle_query(data, client)
            if reply:
                sock.sendto(self._udp_reply(data, reply), client)
        except Exception:
            LOG.exception("Could not send DNS response to %s", client)
        finally:
            slots.release()

    @staticmethod
    def _udp_reply(query_wire, reply_wire):
        """Respect the client's UDP limit; TCP retry is outside this server."""
        limit = 512
        try:
            query = DNSRecord.parse(query_wire)
            for rr in query.ar:
                if rr.rtype == QTYPE.OPT:
                    limit = max(512, min(rr.rclass, 4096))
                    break
        except Exception:
            pass
        if len(reply_wire) <= limit:
            return reply_wire
        reply = DNSRecord.parse(reply_wire)
        reply.header.tc = 1
        reply.header.ad = 0
        reply.rr, reply.auth, reply.ar = [], [], []
        return reply.pack()

    @staticmethod
    def _error(data, request=None, rcode=RCODE.SERVFAIL):
        if request is not None:
            reply = request.reply(aa=0, ra=1)
            reply.header.rcode = rcode
        else:
            ident = int.from_bytes(data[:2], "big") if len(data) >= 2 else 0
            reply = DNSRecord(DNSHeader(id=ident, qr=1, ra=1, rcode=rcode))
        reply.header.ad = 0
        return reply.pack()

    def handle_query(self, data: bytes, client: tuple[str, int]) -> bytes:
        """Evaluate one datagram and log the decision, including failures."""
        start = time.perf_counter()
        request = None
        domain, qtype = "", ""
        decision, category = "error", "malformed"
        try:
            try:
                request = DNSRecord.parse(data)
            except Exception:
                return self._error(data, rcode=RCODE.FORMERR)
            if request.header.qr:
                category = "unexpected-response"
                return b""
            if request.header.opcode != OPCODE.QUERY:
                category = "unsupported-opcode"
                return self._error(data, request, RCODE.NOTIMP)
            if len(request.questions) != 1:
                return self._error(data, request, RCODE.FORMERR)
            domain = normalize_domain(str(request.q.qname))
            qtype = QTYPE[request.q.qtype]
            if request.q.qclass != CLASS.IN:
                category = "unsupported-class"
                return self._error(data, request, RCODE.REFUSED)

            address_query = request.q.qtype in (QTYPE.A, QTYPE.AAAA)
            category = "allowlist"
            if address_query and not self.allowlist.is_allowed(domain):
                category = "blocklist"
                blocked, matched = self.blocklist.is_blocked(domain)
                if blocked:
                    category = f"blocklist:{matched}"
                else:
                    category = "typosquat"
                    blocked, target, distance = self.typosquat.is_lookalike(domain)
                    if blocked:
                        category = f"typosquat:{target}:distance={distance}"
                    else:
                        category = "dga"
                        blocked, _, reason = self.dga.score(domain)
                        if blocked:
                            category = f"dga:{reason}"
                if blocked:
                    decision = "block"
                    ip = config.SINKHOLE_IPV4 if qtype == "A" else config.SINKHOLE_IPV6
                    return self._build_reply(request, [ip], config.SINKHOLE_TTL, qtype).pack()

            # Preserve EDNS and DNSSEC semantics by forwarding those requests.
            cacheable = (address_query and not request.ar and not request.rr
                         and not request.auth and not request.header.cd)
            if cacheable:
                category = "cache"
                hit = self.cache.get(domain, qtype)
                if hit is not None:
                    ttl = hit.remaining_ttl()
                    if ttl > 0:
                        decision, category = "cache", "cache-hit"
                        return self._build_reply(request, hit.answers, ttl, qtype).pack()

            category = "upstream"
            wire = self.upstream.forward(data)
            reply = DNSRecord.parse(wire)
            if (not reply.header.qr or reply.header.id != request.header.id
                    or reply.header.opcode != request.header.opcode
                    or reply.questions != request.questions):
                raise ValueError("Upstream response does not match the query")
            decision = "allow" if reply.header.rcode in (RCODE.NOERROR, RCODE.NXDOMAIN) else "error"
            if (cacheable and reply.header.rcode == RCODE.NOERROR
                    and not reply.header.tc and not reply.header.ad and reply.rr
                    and not reply.auth and not reply.ar
                    and all(rr.rtype == request.q.qtype and rr.rclass == CLASS.IN
                            and rr.rname == request.q.qname for rr in reply.rr)):
                ttl = min(rr.ttl for rr in reply.rr)
                # Skip short TTLs: the component's minimum clamp would extend them.
                if ttl >= config.CACHE_MIN_TTL:
                    self.cache.set(domain, qtype, [str(rr.rdata) for rr in reply.rr], ttl)
            return wire
        except Exception:
            decision = "error"
            LOG.exception("DNS query failed for %s (%s)", domain, qtype)
            return self._error(data, request)
        finally:
            try:
                self.logger.log(client_ip=client[0], domain=domain, qtype=qtype,
                                decision=decision, category=category,
                                latency_ms=(time.perf_counter() - start) * 1000)
            except Exception:
                LOG.exception("Could not log DNS query")

    def _build_reply(self, request, answers: list[str], ttl: int, qtype: str):
        reply = request.reply(aa=0, ra=1)
        reply.header.ad = 0
        data_type = A if qtype == "A" else AAAA
        for ip in answers:
            reply.add_answer(RR(request.q.qname, request.q.qtype, rclass=CLASS.IN,
                                ttl=max(0, int(ttl)), rdata=data_type(ip)))
        return reply
