"""Background feed refresh and atomic replacement of running policy snapshots."""
import logging
import threading
import time

from . import config
from .blocklist import BlocklistChecker
from .feeds import Allowlist, ThreatFeedUpdater

LOG = logging.getLogger(__name__)


class PolicyMaintenance:
    def __init__(self, proxy, *, blocklist=True, allowlist=True, updater=None):
        self.proxy = proxy
        self.blocklist_path = config.DATA_DIR / "blocklist.txt" if blocklist else None
        self.allowlist_path = config.DATA_DIR / "allowlist.txt" if allowlist else None
        self.updater = (ThreatFeedUpdater(blocklist_path=self.blocklist_path)
                        if updater is None and blocklist else updater)
        self._versions = {}
        self._next_feed = 0.0
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, name="dns-policy")
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                LOG.exception("Policy maintenance failed; retaining active policies")
            self._stop.wait(config.POLICY_RELOAD_INTERVAL_SEC)

    def tick(self):
        """Refresh due feeds, then load changed files without partial snapshots."""
        if (self.updater is not None and self.updater.feeds
                and time.monotonic() >= self._next_feed):
            try:
                self.updater.update_daily()
                age = time.time() - self.updater.blocklist_path.stat().st_mtime
                delay = max(1.0, config.FEED_UPDATE_INTERVAL_SEC - max(0, age))
            except Exception:
                # Feed errors can include credentials in their chained causes.
                LOG.warning("Feed refresh failed; retaining the last published blocklist")
                delay = config.FEED_RETRY_INTERVAL_SEC
            self._next_feed = time.monotonic() + delay
        for name, path in (("blocklist", self.blocklist_path),
                           ("allowlist", self.allowlist_path)):
            if path is None:
                continue
            try:
                stat = path.stat()
                version = (stat.st_mtime_ns, stat.st_size, stat.st_ino)
                if self._versions.get(name) == version:
                    continue
                snapshot = BlocklistChecker() if name == "blocklist" else Allowlist(path)
                if name == "blocklist":
                    snapshot.load_file(path, strict=True)
                setattr(self.proxy, name, snapshot)
                self._versions[name] = version
                LOG.info("Reloaded %s policy", name)
            except FileNotFoundError:
                # Removing a file must not silently remove an active policy.
                continue
            except (OSError, UnicodeError, ValueError):
                LOG.warning("Could not reload %s; retaining active policy", name)

    def close(self):
        self._stop.set()
        if self._thread is not None and self._thread.ident is not None:
            self._thread.join()
