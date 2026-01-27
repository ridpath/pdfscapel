"""Parallel processing utilities for PDFAutopsy

This module provides:
- Multiprocessing patterns for page processing
- Threading patterns for I/O-bound tasks
- Worker pool management
- Batch processing utilities
- Progress tracking for parallel operations
"""

import multiprocessing as mp
from multiprocessing import Pool, Queue, Manager
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from typing import Any, Callable, Iterable, List, Optional, TypeVar, Iterator, Tuple
from pathlib import Path
import os

from pdfscalpel.core.logging import get_logger

logger = get_logger(__name__)

T = TypeVar('T')
R = TypeVar('R')


def get_optimal_workers(task_type: str = 'cpu') -> int:
    """
    Get optimal number of workers based on task type
    
    Args:
        task_type: 'cpu' for CPU-bound, 'io' for I/O-bound
    
    Returns:
        Number of workers to use
    """
    cpu_count = mp.cpu_count()
    
    if task_type == 'cpu':
        # For CPU-bound tasks, use all cores minus one
        return max(1, cpu_count - 1)
    elif task_type == 'io':
        # For I/O-bound tasks, can use more threads
        return cpu_count * 2
    else:
        return cpu_count


class ParallelPageProcessor:
    """Process PDF pages in parallel"""
    
    def __init__(self, num_workers: Optional[int] = None):
        self.num_workers = num_workers or get_optimal_workers('cpu')
    
    def process_pages(self, pdf_path: Path, processor_func: Callable,
                     *args, **kwargs) -> List[Any]:
        """
        Process all pages of a PDF in parallel
        
        Args:
            pdf_path: Path to PDF file
            processor_func: Function to apply to each page
            *args, **kwargs: Additional arguments for processor
        
        Returns:
            List of results from processor function
        """
        import pikepdf
        
        with pikepdf.Pdf.open(pdf_path) as pdf:
            num_pages = len(pdf.pages)
            
            # Create tasks for each page
            tasks = [(pdf_path, i, processor_func, args, kwargs) 
                    for i in range(num_pages)]
            
            with Pool(processes=self.num_workers) as pool:
                results = pool.starmap(_process_single_page, tasks)
            
            return results
    
    def process_page_batches(self, pdf_path: Path, processor_func: Callable,
                            batch_size: int = 10, *args, **kwargs) -> List[Any]:
        """
        Process pages in batches for better memory efficiency
        
        Args:
            pdf_path: Path to PDF file
            processor_func: Function to apply to each batch
            batch_size: Number of pages per batch
            *args, **kwargs: Additional arguments for processor
        
        Returns:
            List of results from processor function
        """
        import pikepdf
        
        with pikepdf.Pdf.open(pdf_path) as pdf:
            num_pages = len(pdf.pages)
            batches = [(pdf_path, i, min(i + batch_size, num_pages), 
                       processor_func, args, kwargs)
                      for i in range(0, num_pages, batch_size)]
            
            with Pool(processes=self.num_workers) as pool:
                results = pool.starmap(_process_page_batch, batches)
            
            return results


def _process_single_page(pdf_path: Path, page_idx: int, processor_func: Callable,
                        args: tuple, kwargs: dict) -> Any:
    """Worker function for processing a single page"""
    import pikepdf
    
    try:
        with pikepdf.Pdf.open(pdf_path) as pdf:
            page = pdf.pages[page_idx]
            return processor_func(page, *args, **kwargs)
    except Exception as e:
        logger.error(f"Error processing page {page_idx}: {e}")
        return None


def _process_page_batch(pdf_path: Path, start_idx: int, end_idx: int,
                       processor_func: Callable, args: tuple, kwargs: dict) -> Any:
    """Worker function for processing a batch of pages"""
    import pikepdf
    
    try:
        with pikepdf.Pdf.open(pdf_path) as pdf:
            pages = pdf.pages[start_idx:end_idx]
            return processor_func(pages, *args, **kwargs)
    except Exception as e:
        logger.error(f"Error processing pages {start_idx}-{end_idx}: {e}")
        return None


class ParallelFileProcessor:
    """Process multiple PDF files in parallel"""
    
    def __init__(self, num_workers: Optional[int] = None):
        self.num_workers = num_workers or get_optimal_workers('io')
    
    def process_files(self, file_paths: List[Path], processor_func: Callable,
                     *args, **kwargs) -> List[Any]:
        """
        Process multiple files in parallel
        
        Args:
            file_paths: List of PDF paths
            processor_func: Function to apply to each file
            *args, **kwargs: Additional arguments for processor
        
        Returns:
            List of results from processor function
        """
        with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
            futures = []
            for path in file_paths:
                future = executor.submit(processor_func, path, *args, **kwargs)
                futures.append((path, future))
            
            results = []
            for path, future in futures:
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error processing {path}: {e}")
                    results.append(None)
            
            return results


class ParallelMapper:
    """Generic parallel mapper for various tasks"""
    
    def __init__(self, num_workers: Optional[int] = None, use_threads: bool = False):
        self.num_workers = num_workers or get_optimal_workers('io' if use_threads else 'cpu')
        self.use_threads = use_threads
    
    def map(self, func: Callable[[T], R], items: Iterable[T],
           chunksize: int = 1) -> List[R]:
        """
        Map function over items in parallel
        
        Args:
            func: Function to apply
            items: Items to process
            chunksize: Chunk size for load balancing
        
        Returns:
            List of results
        """
        items_list = list(items)
        
        if self.use_threads:
            with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
                results = list(executor.map(func, items_list, chunksize=chunksize))
        else:
            with ProcessPoolExecutor(max_workers=self.num_workers) as executor:
                results = list(executor.map(func, items_list, chunksize=chunksize))
        
        return results
    
    def starmap(self, func: Callable, items: Iterable[tuple]) -> List[Any]:
        """
        Starmap function over items in parallel
        
        Args:
            func: Function to apply
            items: Tuples of arguments
        
        Returns:
            List of results
        """
        items_list = list(items)
        
        if self.use_threads:
            with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
                futures = [executor.submit(func, *args) for args in items_list]
                results = [f.result() for f in futures]
        else:
            with Pool(processes=self.num_workers) as pool:
                results = pool.starmap(func, items_list)
        
        return results


class ParallelBatchProcessor:
    """Process large collections in batches with parallel processing"""
    
    def __init__(self, batch_size: int = 100, num_workers: Optional[int] = None):
        self.batch_size = batch_size
        self.num_workers = num_workers or get_optimal_workers('cpu')
    
    def process_batches(self, items: Iterable[T], processor_func: Callable[[List[T]], R],
                       *args, **kwargs) -> List[R]:
        """
        Process items in batches, with parallel batch processing
        
        Args:
            items: Items to process
            processor_func: Function that processes a batch
            *args, **kwargs: Additional arguments
        
        Returns:
            List of batch results
        """
        batches = self._create_batches(items)
        
        with Pool(processes=self.num_workers) as pool:
            tasks = [(batch, processor_func, args, kwargs) for batch in batches]
            results = pool.starmap(_process_batch, tasks)
        
        return results
    
    def _create_batches(self, items: Iterable[T]) -> List[List[T]]:
        """Split items into batches"""
        items_list = list(items)
        batches = []
        
        for i in range(0, len(items_list), self.batch_size):
            batch = items_list[i:i + self.batch_size]
            batches.append(batch)
        
        return batches


def _process_batch(batch: List[T], processor_func: Callable, 
                  args: tuple, kwargs: dict) -> Any:
    """Worker function for batch processing"""
    try:
        return processor_func(batch, *args, **kwargs)
    except Exception as e:
        logger.error(f"Error processing batch: {e}")
        return None


class ProgressTracker:
    """Track progress for parallel operations using shared memory"""
    
    def __init__(self, total: int):
        self.total = total
        self.manager = Manager()
        self.counter = self.manager.Value('i', 0)
        self.lock = self.manager.Lock()
    
    def increment(self, n: int = 1):
        """Increment progress counter"""
        with self.lock:
            self.counter.value += n
    
    def get_progress(self) -> tuple[int, float]:
        """Get current progress"""
        with self.lock:
            current = self.counter.value
            percentage = (current / self.total * 100) if self.total > 0 else 0
            return current, percentage


def parallel_map_with_progress(func: Callable[[T], R], items: List[T],
                               desc: str = "Processing",
                               num_workers: Optional[int] = None) -> List[R]:
    """
    Map function over items with progress tracking
    
    Args:
        func: Function to apply
        items: Items to process
        desc: Progress description
        num_workers: Number of workers
    
    Returns:
        List of results
    """
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
    
    num_workers = num_workers or get_optimal_workers('cpu')
    results = [None] * len(items)
    
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
    ) as progress:
        task = progress.add_task(desc, total=len(items))
        
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = {executor.submit(func, item): i for i, item in enumerate(items)}
            
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    logger.error(f"Error processing item {idx}: {e}")
                    results[idx] = None
                
                progress.update(task, advance=1)
    
    return results


def parallel_file_operation(operation: str, file_paths: List[Path],
                           output_dir: Optional[Path] = None,
                           num_workers: Optional[int] = None) -> List[bool]:
    """
    Perform an operation on multiple files in parallel
    
    Args:
        operation: Operation name (for import)
        file_paths: List of files to process
        output_dir: Output directory
        num_workers: Number of workers
    
    Returns:
        List of success flags
    """
    num_workers = num_workers or get_optimal_workers('io')
    
    tasks = [(operation, path, output_dir) for path in file_paths]
    
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        results = list(executor.map(lambda t: _execute_file_operation(*t), tasks))
    
    return results


def _execute_file_operation(operation: str, file_path: Path, 
                           output_dir: Optional[Path]) -> bool:
    """Execute a file operation"""
    try:
        # Placeholder for actual operation execution
        # In real implementation, this would dispatch to specific operations
        logger.info(f"Executing {operation} on {file_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to execute {operation} on {file_path}: {e}")
        return False


class ChunkIterator:
    """Iterator that yields items in chunks for batch processing"""
    
    def __init__(self, items: Iterable[T], chunk_size: int):
        self.items = iter(items)
        self.chunk_size = chunk_size
    
    def __iter__(self) -> Iterator[List[T]]:
        while True:
            chunk = []
            try:
                for _ in range(self.chunk_size):
                    chunk.append(next(self.items))
            except StopIteration:
                if chunk:
                    yield chunk
                break
            
            if chunk:
                yield chunk


def distribute_work(total_items: int, num_workers: int) -> List[Tuple[int, int]]:
    """
    Distribute work evenly across workers
    
    Args:
        total_items: Total number of items to process
        num_workers: Number of workers
    
    Returns:
        List of (start_idx, end_idx) tuples for each worker
    """
    items_per_worker = total_items // num_workers
    remainder = total_items % num_workers
    
    ranges = []
    start = 0
    
    for i in range(num_workers):
        # Distribute remainder across first workers
        worker_items = items_per_worker + (1 if i < remainder else 0)
        end = start + worker_items
        ranges.append((start, end))
        start = end
    
    return ranges
