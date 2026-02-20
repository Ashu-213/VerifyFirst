"""
cache.py — In-memory LRU cache capped at 200 entries.
"""

from collections import OrderedDict
from threading import Lock

MAX_SIZE = 200


class URLCache:
    def __init__(self, max_size: int = MAX_SIZE):
        self._cache: OrderedDict = OrderedDict()
        self._lock = Lock()
        self.max_size = max_size

    def get(self, url: str):
        with self._lock:
            if url not in self._cache:
                return None
            # Move to end (most recently used)
            self._cache.move_to_end(url)
            return self._cache[url]

    def set(self, url: str, result: dict) -> None:
        with self._lock:
            if url in self._cache:
                self._cache.move_to_end(url)
            self._cache[url] = result
            if len(self._cache) > self.max_size:
                # Remove oldest entry
                self._cache.popitem(last=False)

    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


# Module-level singleton
cache = URLCache()
