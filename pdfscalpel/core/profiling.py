"""CPU and memory profiling utilities

This module provides:
- cProfile integration for CPU profiling
- Memory profiling with memory_profiler
- Line-by-line profiling
- Profile visualization and analysis
"""

import cProfile
import pstats
import io
import time
from pathlib import Path
from typing import Callable, Optional, Any
from contextlib import contextmanager
import tempfile

try:
    import memory_profiler
    MEMORY_PROFILER_AVAILABLE = True
except ImportError:
    MEMORY_PROFILER_AVAILABLE = False

try:
    import py_spy
    PY_SPY_AVAILABLE = True
except ImportError:
    PY_SPY_AVAILABLE = False

from pdfscalpel.core.logging import get_logger

logger = get_logger(__name__)


class CPUProfiler:
    """CPU profiler using cProfile"""
    
    def __init__(self):
        self.profiler = cProfile.Profile()
        self.stats: Optional[pstats.Stats] = None
    
    def start(self):
        """Start profiling"""
        self.profiler.enable()
    
    def stop(self):
        """Stop profiling"""
        self.profiler.disable()
    
    def get_stats(self) -> pstats.Stats:
        """Get profiling statistics"""
        if self.stats is None:
            self.stats = pstats.Stats(self.profiler)
        return self.stats
    
    def print_stats(self, sort_by: str = 'cumulative', limit: int = 20):
        """
        Print profiling statistics
        
        Args:
            sort_by: Sort key (cumulative, time, calls, etc.)
            limit: Number of entries to show
        """
        stats = self.get_stats()
        stats.strip_dirs()
        stats.sort_stats(sort_by)
        stats.print_stats(limit)
    
    def save_stats(self, output_path: Path):
        """Save profiling statistics to file"""
        self.profiler.dump_stats(str(output_path))
        logger.info(f"Profile saved to {output_path}")
    
    def generate_report(self) -> str:
        """Generate text report of profiling statistics"""
        s = io.StringIO()
        stats = self.get_stats()
        stats.strip_dirs()
        stats.sort_stats('cumulative')
        stats.stream = s
        stats.print_stats(50)
        return s.getvalue()
    
    @contextmanager
    def profile(self):
        """Context manager for profiling"""
        self.start()
        try:
            yield self
        finally:
            self.stop()


class MemoryProfiler:
    """Memory profiler for tracking allocations"""
    
    def __init__(self):
        if not MEMORY_PROFILER_AVAILABLE:
            logger.warning("memory_profiler not available, install with: pip install memory-profiler")
        self.enabled = MEMORY_PROFILER_AVAILABLE
    
    def profile_function(self, func: Callable) -> Callable:
        """
        Decorator for memory profiling a function
        
        Args:
            func: Function to profile
        
        Returns:
            Wrapped function
        """
        if not self.enabled:
            return func
        
        return memory_profiler.profile(func)
    
    def measure_usage(self, func: Callable, *args, **kwargs) -> tuple[Any, float]:
        """
        Measure memory usage of a function call
        
        Args:
            func: Function to call
            *args, **kwargs: Arguments for function
        
        Returns:
            Tuple of (result, memory_used_mb)
        """
        if not self.enabled:
            result = func(*args, **kwargs)
            return result, 0
        
        import psutil
        import gc
        
        gc.collect()
        process = psutil.Process()
        start_memory = process.memory_info().rss / 1024 / 1024
        
        result = func(*args, **kwargs)
        
        gc.collect()
        end_memory = process.memory_info().rss / 1024 / 1024
        memory_used = end_memory - start_memory
        
        return result, memory_used


class HotPathDetector:
    """Detect hot paths in code execution"""
    
    def __init__(self):
        self.profiler = CPUProfiler()
        self.hot_paths = []
    
    def analyze(self, stats: pstats.Stats, threshold_percent: float = 5.0):
        """
        Analyze profiling stats to detect hot paths
        
        Args:
            stats: Profiling statistics
            threshold_percent: Minimum % of time to be considered hot
        """
        stats.sort_stats('cumulative')
        
        # Get total time
        total_time = sum(stat[2] for stat in stats.stats.values())
        
        hot_paths = []
        for func, (cc, nc, tt, ct, callers) in stats.stats.items():
            percent = (ct / total_time * 100) if total_time > 0 else 0
            
            if percent >= threshold_percent:
                hot_paths.append({
                    'function': func,
                    'cumulative_time': ct,
                    'percent': percent,
                    'calls': cc,
                })
        
        self.hot_paths = sorted(hot_paths, key=lambda x: x['percent'], reverse=True)
        return self.hot_paths
    
    def print_hot_paths(self):
        """Print detected hot paths"""
        print("\nHot Paths (>5% execution time):")
        print("=" * 80)
        
        for i, path in enumerate(self.hot_paths[:10], 1):
            func = path['function']
            filename = func[0] if func[0] != '~' else '<builtin>'
            line = func[1]
            name = func[2]
            
            print(f"{i}. {name} ({filename}:{line})")
            print(f"   Time: {path['cumulative_time']:.4f}s ({path['percent']:.1f}%)")
            print(f"   Calls: {path['calls']}")
            print()


def profile_operation(func: Callable, *args, output_path: Optional[Path] = None, 
                     **kwargs) -> Any:
    """
    Profile a function call and optionally save results
    
    Args:
        func: Function to profile
        *args, **kwargs: Arguments for function
        output_path: Optional path to save profile
    
    Returns:
        Function result
    """
    profiler = CPUProfiler()
    
    with profiler.profile():
        result = func(*args, **kwargs)
    
    # Print stats
    print("\nCPU Profiling Results:")
    print("=" * 80)
    profiler.print_stats(limit=20)
    
    # Detect hot paths
    detector = HotPathDetector()
    detector.analyze(profiler.get_stats())
    detector.print_hot_paths()
    
    # Save if requested
    if output_path:
        profiler.save_stats(output_path)
    
    return result


def compare_performance(func1: Callable, func2: Callable, 
                       args1: tuple = (), args2: tuple = (),
                       kwargs1: dict = None, kwargs2: dict = None,
                       runs: int = 10) -> dict:
    """
    Compare performance of two functions
    
    Args:
        func1: First function
        func2: Second function
        args1: Args for func1
        args2: Args for func2
        kwargs1: Kwargs for func1
        kwargs2: Kwargs for func2
        runs: Number of runs for averaging
    
    Returns:
        Dict with comparison results
    """
    kwargs1 = kwargs1 or {}
    kwargs2 = kwargs2 or {}
    
    # Benchmark func1
    times1 = []
    for _ in range(runs):
        start = time.perf_counter()
        func1(*args1, **kwargs1)
        times1.append(time.perf_counter() - start)
    
    # Benchmark func2
    times2 = []
    for _ in range(runs):
        start = time.perf_counter()
        func2(*args2, **kwargs2)
        times2.append(time.perf_counter() - start)
    
    avg1 = sum(times1) / len(times1)
    avg2 = sum(times2) / len(times2)
    
    return {
        'func1_name': func1.__name__,
        'func2_name': func2.__name__,
        'func1_avg': avg1,
        'func2_avg': avg2,
        'speedup': avg2 / avg1 if avg1 > 0 else float('inf'),
        'winner': func1.__name__ if avg1 < avg2 else func2.__name__,
    }


def detect_memory_leaks(func: Callable, iterations: int = 100,
                       *args, **kwargs) -> dict:
    """
    Detect potential memory leaks by running function repeatedly
    
    Args:
        func: Function to test
        iterations: Number of iterations
        *args, **kwargs: Arguments for function
    
    Returns:
        Dict with leak detection results
    """
    try:
        import psutil
        import gc
    except ImportError:
        logger.error("psutil required for memory leak detection")
        return {'error': 'psutil not available'}
    
    process = psutil.Process()
    memory_samples = []
    
    for i in range(iterations):
        gc.collect()
        start_memory = process.memory_info().rss / 1024 / 1024
        
        func(*args, **kwargs)
        
        gc.collect()
        end_memory = process.memory_info().rss / 1024 / 1024
        memory_samples.append(end_memory)
        
        if i % 10 == 0:
            logger.debug(f"Iteration {i}: {end_memory:.2f}MB")
    
    # Analyze trend
    if len(memory_samples) < 10:
        return {'error': 'Not enough samples'}
    
    first_avg = sum(memory_samples[:10]) / 10
    last_avg = sum(memory_samples[-10:]) / 10
    growth = last_avg - first_avg
    growth_percent = (growth / first_avg * 100) if first_avg > 0 else 0
    
    # Simple heuristic: >10% growth suggests potential leak
    potential_leak = growth_percent > 10
    
    return {
        'iterations': iterations,
        'start_memory_mb': memory_samples[0],
        'end_memory_mb': memory_samples[-1],
        'growth_mb': growth,
        'growth_percent': growth_percent,
        'potential_leak': potential_leak,
        'samples': memory_samples,
    }


def generate_flame_graph(profile_path: Path, output_path: Path):
    """
    Generate flame graph from profile data
    
    Requires: flamegraph.pl or py-spy
    
    Args:
        profile_path: Path to profile data
        output_path: Path for flame graph SVG
    """
    import subprocess
    
    try:
        # Try using py-spy to generate flame graph
        subprocess.run([
            'py-spy', 'flame', 
            '--profile', str(profile_path),
            '--output', str(output_path)
        ], check=True)
        
        logger.info(f"Flame graph saved to {output_path}")
    except FileNotFoundError:
        logger.error("py-spy not found. Install with: pip install py-spy")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate flame graph: {e}")


@contextmanager
def profile_context(name: str = "Operation", 
                   save_path: Optional[Path] = None,
                   print_stats: bool = True):
    """
    Context manager for profiling a block of code
    
    Args:
        name: Name of operation
        save_path: Optional path to save profile
        print_stats: Whether to print statistics
    
    Example:
        with profile_context("PDF Processing"):
            process_large_pdf()
    """
    profiler = CPUProfiler()
    
    logger.info(f"Starting profiling: {name}")
    profiler.start()
    
    try:
        yield profiler
    finally:
        profiler.stop()
        
        if print_stats:
            print(f"\n{name} - CPU Profiling Results:")
            print("=" * 80)
            profiler.print_stats(limit=15)
        
        if save_path:
            profiler.save_stats(save_path)


def optimize_hot_path(func: Callable, test_args: tuple = (), 
                     test_kwargs: dict = None) -> dict:
    """
    Profile function and provide optimization suggestions
    
    Args:
        func: Function to optimize
        test_args: Test arguments
        test_kwargs: Test kwargs
    
    Returns:
        Dict with optimization suggestions
    """
    test_kwargs = test_kwargs or {}
    
    profiler = CPUProfiler()
    
    with profiler.profile():
        func(*test_args, **test_kwargs)
    
    detector = HotPathDetector()
    hot_paths = detector.analyze(profiler.get_stats())
    
    suggestions = []
    
    for path in hot_paths[:5]:
        func_name = path['function'][2]
        percent = path['percent']
        
        if percent > 30:
            suggestions.append({
                'function': func_name,
                'issue': f"Hot path consuming {percent:.1f}% of time",
                'suggestions': [
                    "Consider caching results if function is called repeatedly",
                    "Look for opportunities to optimize loops",
                    "Consider using compiled extensions (Cython/C)",
                ]
            })
        elif percent > 15:
            suggestions.append({
                'function': func_name,
                'issue': f"Significant time spent ({percent:.1f}%)",
                'suggestions': [
                    "Profile this function separately for deeper analysis",
                    "Check for unnecessary allocations",
                    "Consider algorithmic improvements",
                ]
            })
    
    return {
        'hot_paths': hot_paths,
        'suggestions': suggestions,
    }
