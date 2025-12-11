"""Simple TTL-based caching utility for API responses."""
import time
from typing import Any, Dict, Optional, Callable
from functools import wraps
import hashlib
import json


class TTLCache:
    """Time-To-Live cache for API responses."""

    def __init__(self, ttl_seconds: int = 3600):
        """
        Initialize cache with TTL.

        Args:
            ttl_seconds: Time to live in seconds (default: 1 hour)
        """
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}

    def _is_expired(self, entry: Dict[str, Any]) -> bool:
        """Check if cache entry is expired."""
        return time.time() > entry["expires_at"]

    def _make_key(self, *args, **kwargs) -> str:
        """Create a cache key from arguments."""
        # Combine args and kwargs into a single string
        key_data = {
            "args": args,
            "kwargs": sorted(kwargs.items()),
        }
        key_str = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.md5(key_str.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired."""
        if key not in self._cache:
            return None

        entry = self._cache[key]
        if self._is_expired(entry):
            del self._cache[key]
            return None

        return entry["value"]

    def set(self, key: str, value: Any) -> None:
        """Set value in cache with TTL."""
        self._cache[key] = {
            "value": value,
            "expires_at": time.time() + self.ttl_seconds,
        }

    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()

    def cache_async(self, func: Callable):
        """
        Decorator for async functions to enable caching.

        Usage:
            cache = TTLCache(ttl_seconds=3600)

            @cache.cache_async
            async def fetch_data(param):
                return await some_api_call(param)
        """
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            cache_key = f"{func.__name__}:{self._make_key(*args, **kwargs)}"

            # Try to get from cache
            cached_value = self.get(cache_key)
            if cached_value is not None:
                return cached_value

            # Call the actual function
            result = await func(*args, **kwargs)

            # Store in cache
            self.set(cache_key, result)

            return result

        return wrapper


# Global cache instances with different TTLs
pypi_cache = TTLCache(ttl_seconds=3600)  # 1 hour for PyPI metadata
osv_cache = TTLCache(ttl_seconds=3600)   # 1 hour for OSV vulnerability data
github_cache = TTLCache(ttl_seconds=1800)  # 30 minutes for GitHub data
