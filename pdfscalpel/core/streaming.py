"""Streaming parsers for large PDF files

This module provides memory-efficient streaming parsers that:
- Use memory-mapped file I/O for 1GB+ PDFs
- Avoid loading entire PDF into memory
- Support incremental parsing (stop early when target found)
- Handle large object streams efficiently
"""

import mmap
import re
from pathlib import Path
from typing import Iterator, Optional, Tuple, List, Dict, Any, BinaryIO
from io import BytesIO
import zlib

from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import PDFScalpelError

logger = get_logger(__name__)


class StreamingPDFReader:
    """Memory-efficient PDF reader using memory-mapped I/O"""
    
    def __init__(self, path: Path, use_mmap: bool = True):
        self.path = Path(path)
        self.use_mmap = use_mmap
        self.file_handle: Optional[BinaryIO] = None
        self.mmap_handle: Optional[mmap.mmap] = None
        self.file_size = self.path.stat().st_size
        
        # Use mmap for files > 10MB
        if self.file_size > 10 * 1024 * 1024:
            self.use_mmap = True
    
    def __enter__(self):
        self.file_handle = open(self.path, 'rb')
        
        if self.use_mmap:
            try:
                self.mmap_handle = mmap.mmap(
                    self.file_handle.fileno(),
                    length=0,
                    access=mmap.ACCESS_READ
                )
                logger.debug(f"Opened {self.path} with mmap ({self.file_size / 1024 / 1024:.2f}MB)")
            except Exception as e:
                logger.warning(f"Failed to create mmap, falling back to regular I/O: {e}")
                self.use_mmap = False
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.mmap_handle:
            self.mmap_handle.close()
        if self.file_handle:
            self.file_handle.close()
    
    def read_chunk(self, offset: int, size: int) -> bytes:
        """Read a chunk from the file"""
        if self.mmap_handle:
            return self.mmap_handle[offset:offset + size]
        else:
            self.file_handle.seek(offset)
            return self.file_handle.read(size)
    
    def search(self, pattern: bytes, start: int = 0, end: Optional[int] = None) -> Optional[int]:
        """Search for pattern in file"""
        if end is None:
            end = self.file_size
        
        if self.mmap_handle:
            try:
                pos = self.mmap_handle.find(pattern, start, end)
                return pos if pos != -1 else None
            except Exception:
                return None
        else:
            chunk_size = 1024 * 1024  # 1MB chunks
            overlap = len(pattern)
            
            self.file_handle.seek(start)
            pos = start
            
            while pos < end:
                chunk = self.file_handle.read(min(chunk_size, end - pos))
                if not chunk:
                    break
                
                idx = chunk.find(pattern)
                if idx != -1:
                    return pos + idx
                
                pos += len(chunk) - overlap
                if pos >= end:
                    break
                self.file_handle.seek(pos)
            
            return None
    
    def search_all(self, pattern: bytes, max_results: Optional[int] = None) -> Iterator[int]:
        """Search for all occurrences of pattern"""
        start = 0
        count = 0
        
        while True:
            pos = self.search(pattern, start)
            if pos is None:
                break
            
            yield pos
            count += 1
            
            if max_results and count >= max_results:
                break
            
            start = pos + 1
    
    def read_all(self) -> bytes:
        """Read entire file (use with caution for large files)"""
        if self.mmap_handle:
            return self.mmap_handle[:]
        else:
            self.file_handle.seek(0)
            return self.file_handle.read()


class IncrementalObjectParser:
    """Parse PDF objects incrementally without loading entire PDF"""
    
    def __init__(self, reader: StreamingPDFReader):
        self.reader = reader
    
    def find_objects(self, obj_type: Optional[str] = None, 
                    stop_on_first: bool = False) -> Iterator[Tuple[int, int, bytes]]:
        """
        Find PDF objects in file
        
        Args:
            obj_type: Filter by object type (e.g., '/JavaScript', '/EmbeddedFile')
            stop_on_first: Stop after finding first match
        
        Yields:
            Tuple of (object_number, generation, object_data)
        """
        # Find all object declarations
        obj_pattern = rb'(\d+)\s+(\d+)\s+obj'
        
        for match_pos in self.reader.search_all(obj_pattern):
            # Read surrounding context
            start = max(0, match_pos - 10)
            chunk_size = 50000  # 50KB should cover most objects
            chunk = self.reader.read_chunk(start, chunk_size)
            
            # Extract object
            obj_match = re.search(obj_pattern, chunk)
            if not obj_match:
                continue
            
            obj_num = int(obj_match.group(1))
            obj_gen = int(obj_match.group(2))
            
            # Find endobj
            endobj_pos = chunk.find(b'endobj', obj_match.end())
            if endobj_pos == -1:
                # Object larger than chunk, read more
                extended_chunk = self.reader.read_chunk(start, chunk_size * 4)
                endobj_pos = extended_chunk.find(b'endobj', obj_match.end())
                if endobj_pos != -1:
                    chunk = extended_chunk
            
            if endobj_pos == -1:
                logger.warning(f"Could not find endobj for object {obj_num}")
                continue
            
            obj_data = chunk[obj_match.start():endobj_pos + 6]
            
            # Filter by type if requested
            if obj_type:
                if obj_type.encode() not in obj_data:
                    continue
            
            yield (obj_num, obj_gen, obj_data)
            
            if stop_on_first:
                break
    
    def extract_streams(self, decompress: bool = True, 
                       max_stream_size: Optional[int] = None) -> Iterator[Tuple[int, bytes]]:
        """
        Extract all streams from PDF
        
        Args:
            decompress: Attempt to decompress streams
            max_stream_size: Skip streams larger than this (bytes)
        
        Yields:
            Tuple of (object_number, stream_data)
        """
        stream_pattern = rb'stream\s*\n'
        
        for obj_num, obj_gen, obj_data in self.find_objects():
            # Check if object contains stream
            stream_match = re.search(stream_pattern, obj_data)
            if not stream_match:
                continue
            
            # Extract stream
            stream_start = stream_match.end()
            endstream_match = re.search(rb'\s*endstream', obj_data[stream_start:])
            
            if not endstream_match:
                continue
            
            stream_data = obj_data[stream_start:stream_start + endstream_match.start()]
            
            # Check size limit
            if max_stream_size and len(stream_data) > max_stream_size:
                logger.debug(f"Skipping large stream in object {obj_num}: {len(stream_data)} bytes")
                continue
            
            # Decompress if requested
            if decompress:
                # Check for FlateDecode filter
                if b'/FlateDecode' in obj_data or b'/Fl' in obj_data:
                    try:
                        stream_data = zlib.decompress(stream_data)
                    except Exception as e:
                        logger.debug(f"Failed to decompress stream in object {obj_num}: {e}")
            
            yield (obj_num, stream_data)


class IncrementalTextExtractor:
    """Extract text incrementally from large PDFs"""
    
    def __init__(self, reader: StreamingPDFReader):
        self.reader = reader
        self.parser = IncrementalObjectParser(reader)
    
    def extract_text_chunks(self, chunk_size: int = 10) -> Iterator[str]:
        """
        Extract text in chunks (by page ranges)
        
        Args:
            chunk_size: Number of pages per chunk
        
        Yields:
            Text content from each chunk
        """
        # This is a simplified implementation
        # Full implementation would require parsing page objects
        
        for obj_num, stream_data in self.parser.extract_streams():
            # Look for text operators
            if b'Tj' in stream_data or b'TJ' in stream_data or b'Td' in stream_data:
                try:
                    # Extract text between parentheses
                    text_matches = re.findall(rb'\(([^)]+)\)', stream_data)
                    if text_matches:
                        text = b' '.join(text_matches).decode('latin-1', errors='ignore')
                        yield text
                except Exception as e:
                    logger.debug(f"Failed to extract text from object {obj_num}: {e}")


class PatternScanner:
    """Scan large PDFs for patterns efficiently"""
    
    def __init__(self, reader: StreamingPDFReader):
        self.reader = reader
    
    def scan_for_pattern(self, pattern: bytes, context_size: int = 100,
                        max_matches: Optional[int] = None) -> Iterator[Tuple[int, bytes]]:
        """
        Scan for pattern with surrounding context
        
        Args:
            pattern: Pattern to search for
            context_size: Bytes of context before/after match
            max_matches: Stop after N matches
        
        Yields:
            Tuple of (offset, context)
        """
        count = 0
        
        for offset in self.reader.search_all(pattern):
            start = max(0, offset - context_size)
            end = min(self.reader.file_size, offset + len(pattern) + context_size)
            context = self.reader.read_chunk(start, end - start)
            
            yield (offset, context)
            
            count += 1
            if max_matches and count >= max_matches:
                break
    
    def scan_regex(self, pattern: str, encoding: str = 'latin-1',
                  chunk_size: int = 1024 * 1024) -> Iterator[Tuple[int, str]]:
        """
        Scan for regex pattern
        
        Args:
            pattern: Regex pattern
            encoding: Text encoding
            chunk_size: Chunk size for scanning
        
        Yields:
            Tuple of (offset, matched_text)
        """
        regex = re.compile(pattern.encode(encoding))
        overlap = 1000  # Overlap to catch matches across chunks
        
        offset = 0
        while offset < self.reader.file_size:
            chunk = self.reader.read_chunk(offset, chunk_size)
            if not chunk:
                break
            
            for match in regex.finditer(chunk):
                matched_text = match.group(0).decode(encoding, errors='ignore')
                yield (offset + match.start(), matched_text)
            
            offset += len(chunk) - overlap
            if offset >= self.reader.file_size:
                break


class ChunkedProcessor:
    """Process large PDFs in chunks to manage memory"""
    
    def __init__(self, path: Path, chunk_size: int = 10):
        self.path = path
        self.chunk_size = chunk_size
    
    def process_pages(self, processor_func, *args, **kwargs) -> Iterator[Any]:
        """
        Process PDF pages in chunks
        
        Args:
            processor_func: Function to call on each page chunk
            *args, **kwargs: Arguments for processor function
        
        Yields:
            Results from processor function
        """
        import pikepdf
        
        with pikepdf.Pdf.open(self.path) as pdf:
            total_pages = len(pdf.pages)
            
            for start_idx in range(0, total_pages, self.chunk_size):
                end_idx = min(start_idx + self.chunk_size, total_pages)
                pages = pdf.pages[start_idx:end_idx]
                
                result = processor_func(pages, *args, **kwargs)
                yield result


def estimate_memory_for_file(file_size: int) -> Dict[str, Any]:
    """
    Estimate memory requirements for processing a PDF
    
    Args:
        file_size: File size in bytes
    
    Returns:
        Dict with memory estimates
    """
    file_size_mb = file_size / 1024 / 1024
    
    # Rough estimates based on testing
    if file_size_mb < 10:
        estimated_memory = file_size_mb * 3
        use_streaming = False
    elif file_size_mb < 100:
        estimated_memory = file_size_mb * 2
        use_streaming = True
    else:
        estimated_memory = min(file_size_mb * 1.5, 1000)  # Cap at 1GB
        use_streaming = True
    
    return {
        'file_size_mb': file_size_mb,
        'estimated_memory_mb': estimated_memory,
        'use_streaming': use_streaming,
        'use_mmap': file_size_mb > 10,
        'chunk_processing': file_size_mb > 50,
    }
