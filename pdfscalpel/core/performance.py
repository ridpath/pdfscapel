"""Performance optimization utilities for PDFAutopsy

This module provides:
- Caching for expensive operations
- Memory profiling and monitoring
- CPU profiling utilities
- Performance benchmarking
- Lazy loading mechanisms
"""

import functools
import time
import sys
import os
import gc
from typing import Any, Callable, Dict, Optional, TypeVar, cast
from pathlib import Path
from collections import OrderedDict
from threading import RLock
import hashlib
import pickle

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from pdfscalpel.core.logging import get_logger

logger = get_logger(__name__)

F = TypeVar('F', bound=Callable[..., Any])


class LRUCache:
    """Thread-safe LRU cache implementation for expensive operations"""
    
    def __init__(self, maxsize: int = 128):
        self.cache: OrderedDict = OrderedDict()
        self.maxsize = maxsize
        self.lock = RLock()
        self.hits = 0
        self.misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
                self.hits += 1
                return self.cache[key]
            self.misses += 1
            return None
    
    def put(self, key: str, value: Any):
        """Put value in cache"""
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            if len(self.cache) > self.maxsize:
                self.cache.popitem(last=False)
    
    def clear(self):
        """Clear cache"""
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0
    
    def stats(self) -> Dict[str, int]:
        """Get cache statistics"""
        with self.lock:
            total = self.hits + self.misses
            hit_rate = (self.hits / total * 100) if total > 0 else 0
            return {
                'hits': self.hits,
                'misses': self.misses,
                'size': len(self.cache),
                'maxsize': self.maxsize,
                'hit_rate': hit_rate
            }


# Global caches for different operations
_pdf_structure_cache = LRUCache(maxsize=64)
_metadata_cache = LRUCache(maxsize=128)
_object_cache = LRUCache(maxsize=256)
_hash_cache = LRUCache(maxsize=512)


def cached_operation(cache: LRUCache, key_func: Optional[Callable] = None):
    """
    Decorator for caching expensive operations
    
    Args:
        cache: LRUCache instance to use
        key_func: Optional function to generate cache key from args
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = _default_cache_key(func.__name__, args, kwargs)
            
            # Check cache
            result = cache.get(cache_key)
            if result is not None:
                logger.debug(f"Cache hit for {func.__name__}: {cache_key[:50]}")
                return result
            
            # Compute and cache
            result = func(*args, **kwargs)
            cache.put(cache_key, result)
            logger.debug(f"Cache miss for {func.__name__}: {cache_key[:50]}")
            return result
        
        return cast(F, wrapper)
    return decorator


def _default_cache_key(func_name: str, args: tuple, kwargs: dict) -> str:
    """Generate default cache key from function name and arguments"""
    try:
        key_parts = [func_name]
        for arg in args:
            if isinstance(arg, (str, int, float, bool)):
                key_parts.append(str(arg))
            elif isinstance(arg, Path):
                key_parts.append(str(arg))
            elif hasattr(arg, '__class__'):
                key_parts.append(arg.__class__.__name__)
        
        for k, v in sorted(kwargs.items()):
            if isinstance(v, (str, int, float, bool)):
                key_parts.append(f"{k}={v}")
        
        return "|".join(key_parts)
    except Exception:
        return func_name


def timed_operation(func: F) -> F:
    """Decorator to measure function execution time"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            elapsed = time.perf_counter() - start
            logger.debug(f"{func.__name__} took {elapsed:.4f}s")
    return cast(F, wrapper)


class MemoryMonitor:
    """Monitor memory usage during operations"""
    
    def __init__(self, name: str = "Operation"):
        self.name = name
        self.start_memory = 0
        self.peak_memory = 0
        
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil not available, memory monitoring disabled")
    
    def __enter__(self):
        if PSUTIL_AVAILABLE:
            gc.collect()
            process = psutil.Process()
            self.start_memory = process.memory_info().rss / 1024 / 1024  # MB
            self.peak_memory = self.start_memory
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if PSUTIL_AVAILABLE:
            process = psutil.Process()
            end_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_used = end_memory - self.start_memory
            
            logger.info(
                f"{self.name}: "
                f"Start={self.start_memory:.2f}MB, "
                f"End={end_memory:.2f}MB, "
                f"Used={memory_used:.2f}MB, "
                f"Peak={self.peak_memory:.2f}MB"
            )
    
    def update_peak(self):
        """Update peak memory usage"""
        if PSUTIL_AVAILABLE:
            process = psutil.Process()
            current = process.memory_info().rss / 1024 / 1024
            self.peak_memory = max(self.peak_memory, current)


class PerformanceProfiler:
    """Profile CPU and memory performance"""
    
    def __init__(self, name: str = "Operation", enabled: bool = True):
        self.name = name
        self.enabled = enabled
        self.start_time = 0
        self.start_memory = 0
    
    def __enter__(self):
        if self.enabled:
            self.start_time = time.perf_counter()
            if PSUTIL_AVAILABLE:
                gc.collect()
                process = psutil.Process()
                self.start_memory = process.memory_info().rss / 1024 / 1024
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.enabled:
            elapsed = time.perf_counter() - self.start_time
            
            log_msg = f"{self.name}: Time={elapsed:.4f}s"
            
            if PSUTIL_AVAILABLE:
                process = psutil.Process()
                end_memory = process.memory_info().rss / 1024 / 1024
                memory_used = end_memory - self.start_memory
                log_msg += f", Memory={memory_used:+.2f}MB"
            
            logger.info(log_msg)


class LazyLoader:
    """Lazy load expensive resources on first access"""
    
    def __init__(self, loader_func: Callable):
        self.loader_func = loader_func
        self._value = None
        self._loaded = False
        self._lock = RLock()
    
    def __call__(self):
        if not self._loaded:
            with self._lock:
                if not self._loaded:
                    self._value = self.loader_func()
                    self._loaded = True
        return self._value
    
    def reset(self):
        """Reset lazy loader"""
        with self._lock:
            self._value = None
            self._loaded = False


def compute_file_hash(path: Path, algorithm: str = 'sha256', chunk_size: int = 65536) -> str:
    """
    Compute file hash efficiently using streaming
    
    Args:
        path: File path
        algorithm: Hash algorithm (sha256, md5, sha1)
        chunk_size: Read chunk size for large files
    
    Returns:
        Hex digest of file hash
    """
    cache_key = f"{path}|{algorithm}|{path.stat().st_mtime}"
    cached = _hash_cache.get(cache_key)
    if cached:
        return cached
    
    hasher = hashlib.new(algorithm)
    
    with open(path, 'rb') as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    
    digest = hasher.hexdigest()
    _hash_cache.put(cache_key, digest)
    return digest


class IncrementalParser:
    """Base class for incremental parsing (stop early when data found)"""
    
    def __init__(self, stop_on_first: bool = False):
        self.stop_on_first = stop_on_first
        self.found = False
    
    def should_stop(self) -> bool:
        """Check if parsing should stop"""
        return self.stop_on_first and self.found
    
    def mark_found(self):
        """Mark that target data was found"""
        self.found = True


def get_cache_stats() -> Dict[str, Any]:
    """Get statistics for all caches"""
    return {
        'pdf_structure': _pdf_structure_cache.stats(),
        'metadata': _metadata_cache.stats(),
        'object': _object_cache.stats(),
        'hash': _hash_cache.stats(),
    }


def clear_all_caches():
    """Clear all performance caches"""
    _pdf_structure_cache.clear()
    _metadata_cache.clear()
    _object_cache.clear()
    _hash_cache.clear()
    logger.info("All performance caches cleared")


def get_memory_usage() -> Dict[str, float]:
    """Get current memory usage statistics"""
    if not PSUTIL_AVAILABLE:
        return {'error': 'psutil not available'}
    
    process = psutil.Process()
    mem_info = process.memory_info()
    
    return {
        'rss_mb': mem_info.rss / 1024 / 1024,
        'vms_mb': mem_info.vms / 1024 / 1024,
        'percent': process.memory_percent(),
        'available_mb': psutil.virtual_memory().available / 1024 / 1024,
    }


def optimize_for_large_files(file_size_mb: float) -> Dict[str, Any]:
    """
    Get optimization recommendations for large files
    
    Args:
        file_size_mb: File size in megabytes
    
    Returns:
        Dict with optimization parameters
    """
    if file_size_mb < 10:
        return {
            'use_mmap': False,
            'chunk_size': 65536,
            'cache_objects': True,
            'parallel_processing': False,
        }
    elif file_size_mb < 100:
        return {
            'use_mmap': True,
            'chunk_size': 131072,
            'cache_objects': True,
            'parallel_processing': True,
        }
    else:  # Very large files
        return {
            'use_mmap': True,
            'chunk_size': 262144,
            'cache_objects': False,  # Avoid caching large objects
            'parallel_processing': True,
        }


# Export cache instances for module-level access
pdf_structure_cache = _pdf_structure_cache
metadata_cache = _metadata_cache
object_cache = _object_cache
hash_cache = _hash_cache
