"""Benchmarking utilities for PDFAutopsy

Compare performance against existing tools:
- peepdf, pdfid, pdf-parser, qpdf
- Measure parsing speed, memory usage, throughput
- Generate performance reports
"""

import time
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
import json

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.performance import get_memory_usage

logger = get_logger(__name__)


@dataclass
class BenchmarkResult:
    """Results from a benchmark run"""
    
    tool_name: str
    operation: str
    file_size_mb: float
    num_pages: int
    
    execution_time: float
    memory_used_mb: float
    peak_memory_mb: float
    throughput_pages_per_sec: float
    throughput_mb_per_sec: float
    
    success: bool
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'tool': self.tool_name,
            'operation': self.operation,
            'file_size_mb': self.file_size_mb,
            'num_pages': self.num_pages,
            'execution_time': self.execution_time,
            'memory_used_mb': self.memory_used_mb,
            'peak_memory_mb': self.peak_memory_mb,
            'throughput_pages_per_sec': self.throughput_pages_per_sec,
            'throughput_mb_per_sec': self.throughput_mb_per_sec,
            'success': self.success,
            'error': self.error_message,
            'metadata': self.metadata,
        }


class ToolBenchmarker:
    """Benchmark external tools"""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
    
    def benchmark_tool(self, tool_name: str, command: List[str],
                      pdf_path: Path, operation: str,
                      timeout: int = 300) -> BenchmarkResult:
        """
        Benchmark an external tool
        
        Args:
            tool_name: Name of tool
            command: Command to execute
            pdf_path: PDF file to process
            operation: Operation description
            timeout: Timeout in seconds
        
        Returns:
            BenchmarkResult
        """
        import pikepdf
        
        # Get PDF info
        try:
            with pikepdf.Pdf.open(pdf_path) as pdf:
                num_pages = len(pdf.pages)
        except Exception:
            num_pages = 0
        
        file_size_mb = pdf_path.stat().st_size / 1024 / 1024
        
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil not available, memory tracking disabled")
        
        # Run benchmark
        start_time = time.perf_counter()
        start_memory = 0
        peak_memory = 0
        success = False
        error_msg = None
        
        try:
            if PSUTIL_AVAILABLE:
                parent = psutil.Process()
                start_memory = parent.memory_info().rss / 1024 / 1024
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=tempfile.gettempdir()
            )
            
            # Monitor memory during execution
            if PSUTIL_AVAILABLE:
                try:
                    child = psutil.Process(process.pid)
                    while process.poll() is None:
                        try:
                            mem = child.memory_info().rss / 1024 / 1024
                            peak_memory = max(peak_memory, mem)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            break
                        time.sleep(0.1)
                except Exception:
                    pass
            
            stdout, stderr = process.communicate(timeout=timeout)
            
            if process.returncode == 0:
                success = True
            else:
                error_msg = stderr.decode('utf-8', errors='ignore')[:500]
        
        except subprocess.TimeoutExpired:
            process.kill()
            error_msg = f"Timeout after {timeout}s"
        except FileNotFoundError:
            error_msg = f"Tool not found: {command[0]}"
        except Exception as e:
            error_msg = str(e)
        
        elapsed = time.perf_counter() - start_time
        
        if PSUTIL_AVAILABLE:
            end_memory = psutil.Process().memory_info().rss / 1024 / 1024
            memory_used = end_memory - start_memory
        else:
            memory_used = 0
            peak_memory = 0
        
        # Calculate throughput
        pages_per_sec = num_pages / elapsed if elapsed > 0 and num_pages > 0 else 0
        mb_per_sec = file_size_mb / elapsed if elapsed > 0 else 0
        
        result = BenchmarkResult(
            tool_name=tool_name,
            operation=operation,
            file_size_mb=file_size_mb,
            num_pages=num_pages,
            execution_time=elapsed,
            memory_used_mb=memory_used,
            peak_memory_mb=peak_memory,
            throughput_pages_per_sec=pages_per_sec,
            throughput_mb_per_sec=mb_per_sec,
            success=success,
            error_message=error_msg,
        )
        
        self.results.append(result)
        return result


class PDFAutopsyBenchmarker:
    """Benchmark PDFAutopsy operations"""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
    
    def benchmark_operation(self, operation_name: str, operation_func: Callable,
                           pdf_path: Path, *args, **kwargs) -> BenchmarkResult:
        """
        Benchmark a PDFAutopsy operation
        
        Args:
            operation_name: Name of operation
            operation_func: Function to benchmark
            pdf_path: PDF file to process
            *args, **kwargs: Arguments for operation
        
        Returns:
            BenchmarkResult
        """
        import pikepdf
        import gc
        
        # Get PDF info
        try:
            with pikepdf.Pdf.open(pdf_path) as pdf:
                num_pages = len(pdf.pages)
        except Exception:
            num_pages = 0
        
        file_size_mb = pdf_path.stat().st_size / 1024 / 1024
        
        # Run benchmark
        gc.collect()
        
        start_memory = 0
        if PSUTIL_AVAILABLE:
            start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        start_time = time.perf_counter()
        success = False
        error_msg = None
        
        try:
            result = operation_func(pdf_path, *args, **kwargs)
            success = True
        except Exception as e:
            error_msg = str(e)[:500]
            logger.error(f"Benchmark error: {e}")
        
        elapsed = time.perf_counter() - start_time
        
        end_memory = 0
        if PSUTIL_AVAILABLE:
            end_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        memory_used = end_memory - start_memory if PSUTIL_AVAILABLE else 0
        
        # Calculate throughput
        pages_per_sec = num_pages / elapsed if elapsed > 0 and num_pages > 0 else 0
        mb_per_sec = file_size_mb / elapsed if elapsed > 0 else 0
        
        result = BenchmarkResult(
            tool_name="PDFAutopsy",
            operation=operation_name,
            file_size_mb=file_size_mb,
            num_pages=num_pages,
            execution_time=elapsed,
            memory_used_mb=memory_used,
            peak_memory_mb=end_memory,
            throughput_pages_per_sec=pages_per_sec,
            throughput_mb_per_sec=mb_per_sec,
            success=success,
            error_message=error_msg,
        )
        
        self.results.append(result)
        return result


class BenchmarkSuite:
    """Run comprehensive benchmark suite"""
    
    def __init__(self, test_files: List[Path]):
        self.test_files = test_files
        self.results: List[BenchmarkResult] = []
    
    def run_comparison(self, tools: List[str], operation: str) -> List[BenchmarkResult]:
        """
        Run comparison benchmark across multiple tools
        
        Args:
            tools: List of tool names to benchmark
            operation: Operation to benchmark
        
        Returns:
            List of benchmark results
        """
        results = []
        
        for pdf_path in self.test_files:
            logger.info(f"Benchmarking {pdf_path.name}...")
            
            for tool in tools:
                if tool == 'pdfautopsy':
                    result = self._benchmark_pdfautopsy(pdf_path, operation)
                elif tool == 'qpdf':
                    result = self._benchmark_qpdf(pdf_path)
                elif tool == 'pdfinfo':
                    result = self._benchmark_pdfinfo(pdf_path)
                elif tool == 'pdftk':
                    result = self._benchmark_pdftk(pdf_path)
                else:
                    continue
                
                results.append(result)
                self.results.append(result)
        
        return results
    
    def _benchmark_pdfautopsy(self, pdf_path: Path, operation: str) -> BenchmarkResult:
        """Benchmark PDFAutopsy"""
        benchmarker = PDFAutopsyBenchmarker()
        
        if operation == 'parse':
            from pdfscalpel.core.pdf_base import PDFDocument
            return benchmarker.benchmark_operation('parse', PDFDocument.open, pdf_path)
        else:
            # Placeholder for other operations
            return BenchmarkResult(
                tool_name="PDFAutopsy",
                operation=operation,
                file_size_mb=0,
                num_pages=0,
                execution_time=0,
                memory_used_mb=0,
                peak_memory_mb=0,
                throughput_pages_per_sec=0,
                throughput_mb_per_sec=0,
                success=False,
                error_message="Operation not implemented"
            )
    
    def _benchmark_qpdf(self, pdf_path: Path) -> BenchmarkResult:
        """Benchmark QPDF"""
        benchmarker = ToolBenchmarker()
        output = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False)
        output.close()
        
        try:
            result = benchmarker.benchmark_tool(
                'qpdf',
                ['qpdf', '--check', str(pdf_path)],
                pdf_path,
                'check'
            )
        finally:
            try:
                Path(output.name).unlink()
            except Exception:
                pass
        
        return result
    
    def _benchmark_pdfinfo(self, pdf_path: Path) -> BenchmarkResult:
        """Benchmark pdfinfo (poppler)"""
        benchmarker = ToolBenchmarker()
        return benchmarker.benchmark_tool(
            'pdfinfo',
            ['pdfinfo', str(pdf_path)],
            pdf_path,
            'info'
        )
    
    def _benchmark_pdftk(self, pdf_path: Path) -> BenchmarkResult:
        """Benchmark pdftk"""
        benchmarker = ToolBenchmarker()
        output = tempfile.NamedTemporaryFile(suffix='.txt', delete=False)
        output.close()
        
        try:
            result = benchmarker.benchmark_tool(
                'pdftk',
                ['pdftk', str(pdf_path), 'dump_data', 'output', output.name],
                pdf_path,
                'dump_data'
            )
        finally:
            try:
                Path(output.name).unlink()
            except Exception:
                pass
        
        return result
    
    def generate_report(self, output_path: Optional[Path] = None) -> str:
        """
        Generate benchmark report
        
        Args:
            output_path: Optional path to save report
        
        Returns:
            Report text
        """
        from rich.table import Table
        from rich.console import Console
        
        # Group by operation and file
        grouped = {}
        for result in self.results:
            key = (result.operation, result.file_size_mb)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(result)
        
        report_lines = []
        report_lines.append("PDFAutopsy Performance Benchmark Report")
        report_lines.append(f"Generated: {datetime.now().isoformat()}")
        report_lines.append("=" * 80)
        report_lines.append("")
        
        for (operation, file_size), results in grouped.items():
            report_lines.append(f"Operation: {operation}, File Size: {file_size:.2f}MB")
            report_lines.append("-" * 80)
            
            # Create comparison table
            table = Table()
            table.add_column("Tool")
            table.add_column("Time (s)")
            table.add_column("Memory (MB)")
            table.add_column("Pages/sec")
            table.add_column("MB/sec")
            table.add_column("Success")
            
            for result in results:
                table.add_row(
                    result.tool_name,
                    f"{result.execution_time:.4f}",
                    f"{result.memory_used_mb:.2f}",
                    f"{result.throughput_pages_per_sec:.2f}",
                    f"{result.throughput_mb_per_sec:.2f}",
                    "✓" if result.success else "✗"
                )
            
            console = Console(record=True)
            console.print(table)
            report_lines.append(console.export_text())
            report_lines.append("")
        
        report = "\n".join(report_lines)
        
        if output_path:
            output_path.write_text(report)
            logger.info(f"Report saved to {output_path}")
        
        return report
    
    def save_json(self, output_path: Path):
        """Save results as JSON"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'results': [r.to_dict() for r in self.results]
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Results saved to {output_path}")


def quick_benchmark(pdf_path: Path) -> Dict[str, float]:
    """
    Quick benchmark of common operations on a PDF
    
    Args:
        pdf_path: PDF file to benchmark
    
    Returns:
        Dict with timing results
    """
    import pikepdf
    from pdfscalpel.core.pdf_base import PDFDocument
    
    results = {}
    
    # Benchmark open
    start = time.perf_counter()
    try:
        with PDFDocument.open(pdf_path) as doc:
            num_pages = doc.num_pages
        results['open'] = time.perf_counter() - start
        results['num_pages'] = num_pages
    except Exception as e:
        results['open'] = -1
        results['error'] = str(e)
        return results
    
    # Benchmark metadata extraction
    start = time.perf_counter()
    try:
        with PDFDocument.open(pdf_path) as doc:
            metadata = doc.metadata
        results['metadata'] = time.perf_counter() - start
    except Exception:
        results['metadata'] = -1
    
    # Benchmark object traversal
    start = time.perf_counter()
    try:
        with PDFDocument.open(pdf_path) as doc:
            objects = doc.get_objects()
        results['objects'] = time.perf_counter() - start
        results['num_objects'] = len(objects)
    except Exception:
        results['objects'] = -1
    
    return results
