"""
Web-based PDF Page Extraction

Extract paginated content from web APIs and compile into PDFs.
Useful for:
- Documentation downloads
- API-based writeup systems
- Paginated image archives
- Web-to-PDF workflows
"""

from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
import json
import re
from urllib.parse import unquote

try:
    from PIL import Image
    import io
except ImportError:
    Image = None

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.utils import ImageReader
except ImportError:
    canvas = None

from pdfscalpel.core.http_client import HTTPClient, RetryConfig, RateLimitConfig
from pdfscalpel.core.logging import get_logger

logger = get_logger()


@dataclass
class WebExtractionConfig:
    """Configuration for web extraction"""
    base_url: str
    page_param: str = "page"
    pages: str = "1-100"
    url_template: Optional[str] = None
    
    retry_config: RetryConfig = None
    rate_limit_config: RateLimitConfig = None
    
    cookies: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    cookies_from_browser: Optional[str] = None
    browser_domain: Optional[str] = None
    
    output_format: str = "pdf"
    output_file: Optional[Path] = None
    title: str = "Web Extraction"
    
    min_image_size: int = 1500
    auto_discover: bool = False
    max_discovery_pages: int = 200
    discovery_gap: int = 5
    
    resume_from_cache: bool = True
    cache_dir: Optional[Path] = None
    
    def __post_init__(self):
        if self.retry_config is None:
            self.retry_config = RetryConfig()
        if self.rate_limit_config is None:
            self.rate_limit_config = RateLimitConfig()


def parse_page_range(range_str: str) -> List[int]:
    """
    Parse page range string into list of page numbers
    
    Examples:
        "1-10" -> [1,2,3,4,5,6,7,8,9,10]
        "1,3,5-7" -> [1,3,5,6,7]
        "1-5,10,15-20" -> [1,2,3,4,5,10,15,16,17,18,19,20]
    """
    pages = []
    for part in range_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            pages.extend(range(int(start), int(end) + 1))
        else:
            pages.append(int(part))
    return sorted(set(pages))


def build_url(config: WebExtractionConfig, page: int) -> str:
    """Build URL for specific page"""
    if config.url_template:
        return config.url_template.format(page=page)
    
    if '?' in config.base_url:
        separator = '&'
    else:
        separator = '?'
    
    return f"{config.base_url}{separator}{config.page_param}={page}"


class WebPageExtractor:
    """Extract paginated images from web APIs"""
    
    def __init__(self, config: WebExtractionConfig):
        if not Image:
            raise ImportError("Pillow is required. Install with: pip install Pillow")
        if not canvas:
            raise ImportError("reportlab is required. Install with: pip install reportlab")
        
        self.config = config
        self.client = None
        self.images: List[Optional[bytes]] = []
        self.pages: List[int] = []
        self.stats = {
            'total_pages': 0,
            'downloaded': 0,
            'failed': 0,
            'skipped': 0,
            'retried': 0
        }
    
    def extract(self) -> Path:
        """
        Main extraction workflow
        
        Returns:
            Path to output PDF file
        """
        logger.info(f"Starting web extraction: {self.config.title}")
        
        self._setup_client()
        
        if self.config.auto_discover:
            self.pages = self._discover_pages()
        else:
            self.pages = parse_page_range(self.config.pages)
        
        self.stats['total_pages'] = len(self.pages)
        logger.info(f"Target pages: {len(self.pages)}")
        
        self._download_pages()
        
        self._retry_failed_pages()
        
        output_file = self._generate_output()
        
        self._cleanup()
        
        return output_file
    
    def _setup_client(self):
        """Initialize HTTP client with cookies and headers"""
        cookies = self.config.cookies or {}
        
        headers = self.config.headers or {}
        if cookies.get('XSRF-TOKEN'):
            xsrf_token = unquote(cookies['XSRF-TOKEN'])
            headers['X-XSRF-TOKEN'] = xsrf_token
            logger.debug(f"Added X-XSRF-TOKEN header")
        
        logger.debug(f"Initializing HTTP client with {len(cookies)} cookies")
        logger.debug(f"Cookie names: {list(cookies.keys())}")
        
        self.client = HTTPClient(
            retry_config=self.config.retry_config,
            rate_limit_config=self.config.rate_limit_config,
            cookies=cookies,
            headers=headers
        )
        
        if self.config.cookies_from_browser:
            self.client.load_cookies_from_browser(
                self.config.cookies_from_browser,
                self.config.browser_domain
            )
    
    def _discover_pages(self) -> List[int]:
        """
        Auto-discover available pages by testing URLs
        
        Returns:
            List of valid page numbers
        """
        logger.info("Auto-discovering pages...")
        valid_pages = []
        last_valid = 0
        
        for page in range(1, self.config.max_discovery_pages + 1):
            url = build_url(self.config, page)
            
            try:
                response = self.client.get(url)
                if response and response.status_code == 200:
                    content = response.content
                    if len(content) > self.config.min_image_size:
                        valid_pages.append(page)
                        last_valid = page
                        logger.debug(f"Page {page} valid ({len(content)} bytes)")
                    else:
                        logger.debug(f"Page {page} too small ({len(content)} bytes)")
                else:
                    logger.debug(f"Page {page} not found")
                
                if page - last_valid > self.config.discovery_gap:
                    logger.info(f"Discovery gap reached at page {page}, stopping")
                    break
                
                self.client.rate_limit_delay()
                
            except Exception as e:
                logger.debug(f"Discovery failed for page {page}: {e}")
        
        logger.info(f"Discovered {len(valid_pages)} valid pages (1-{last_valid})")
        return valid_pages
    
    def _download_pages(self):
        """Download all pages"""
        logger.info(f"Downloading {len(self.pages)} pages...")
        
        self.images = [None] * len(self.pages)
        
        for i, page_num in enumerate(self.pages):
            url = build_url(self.config, page_num)
            
            try:
                response = self.client.get(url)
                
                if response and response.status_code == 200:
                    content = response.content
                    content_type = response.headers.get('content-type', 'unknown')
                    
                    if len(content) > self.config.min_image_size:
                        self.images[i] = content
                        self.stats['downloaded'] += 1
                        size_kb = len(content) / 1024
                        
                        if i == 0:
                            logger.info(f"First page content-type: {content_type}")
                            logger.info(f"First 100 bytes: {content[:100]}")
                            
                            try:
                                test_img = Image.open(io.BytesIO(content))
                                logger.info(f"PIL test: format={test_img.format}, size={test_img.size}, mode={test_img.mode}")
                            except Exception as e:
                                logger.error(f"PIL cannot read first page: {e}")
                        
                        logger.info(f"[{i+1}/{len(self.pages)}] Page {page_num} downloaded ({size_kb:.1f} KB)")
                    else:
                        logger.warning(f"[{i+1}/{len(self.pages)}] Page {page_num} too small, skipping")
                        self.stats['skipped'] += 1
                else:
                    logger.warning(f"[{i+1}/{len(self.pages)}] Page {page_num} failed")
                    self.stats['failed'] += 1
            
            except Exception as e:
                logger.error(f"[{i+1}/{len(self.pages)}] Page {page_num} error: {e}")
                self.stats['failed'] += 1
            
            if i < len(self.pages) - 1:
                self.client.rate_limit_delay()
            
            if (i + 1) % 10 == 0:
                self._print_progress()
    
    def _retry_failed_pages(self, max_rounds: int = 3):
        """Retry failed pages with exponential backoff"""
        for round_num in range(1, max_rounds + 1):
            failed_indices = [i for i, img in enumerate(self.images) if img is None]
            
            if not failed_indices:
                logger.info("All pages downloaded successfully")
                break
            
            logger.info(f"\nRetry round {round_num}/{max_rounds}")
            logger.info(f"Retrying {len(failed_indices)} failed pages...")
            
            for idx in failed_indices:
                page_num = self.pages[idx]
                url = build_url(self.config, page_num)
                
                try:
                    response = self.client.get(url)
                    
                    if response and response.status_code == 200:
                        content = response.content
                        if len(content) > self.config.min_image_size:
                            self.images[idx] = content
                            self.stats['downloaded'] += 1
                            self.stats['retried'] += 1
                            self.stats['failed'] -= 1
                            logger.info(f"Page {page_num} recovered")
                
                except Exception as e:
                    logger.debug(f"Retry failed for page {page_num}: {e}")
                
                self.client.rate_limit_delay()
            
            import time
            time.sleep(5 * round_num)
    
    def _generate_output(self) -> Path:
        """Generate output file (PDF or images)"""
        if self.config.output_format == 'pdf':
            return self._create_pdf()
        else:
            raise ValueError(f"Unsupported output format: {self.config.output_format}")
    
    def _create_pdf(self) -> Path:
        """Create PDF from downloaded images"""
        output_file = self.config.output_file or Path(f"{self.config.title.replace(' ', '_')}.pdf")
        
        logger.info(f"Creating PDF: {output_file}")
        
        valid_images = [(i, img) for i, img in enumerate(self.images) if img is not None]
        
        if not valid_images:
            raise ValueError("No valid images to create PDF")
        
        pdf_canvas = canvas.Canvas(str(output_file), pagesize=A4)
        page_width, page_height = A4
        
        pdf_canvas.setTitle(self.config.title)
        
        for page_idx, (img_idx, img_data) in enumerate(valid_images):
            try:
                img_bytes = io.BytesIO(img_data)
                img_bytes.seek(0)
                
                img = Image.open(img_bytes)
                img.load()
                
                img_width, img_height = img.size
                aspect = img_width / img_height
                
                if aspect > (page_width / page_height):
                    draw_width = page_width - 20
                    draw_height = draw_width / aspect
                else:
                    draw_height = page_height - 20
                    draw_width = draw_height * aspect
                
                x = (page_width - draw_width) / 2
                y = (page_height - draw_height) / 2
                
                img_bytes_2 = io.BytesIO(img_data)
                img_bytes_2.seek(0)
                img_reader = ImageReader(img_bytes_2)
                pdf_canvas.drawImage(img_reader, x, y, draw_width, draw_height)
                
                page_num = self.pages[img_idx]
                pdf_canvas.setFont("Helvetica", 8)
                pdf_canvas.drawString(10, 10, f"Page {page_num}")
                
                if page_idx < len(valid_images) - 1:
                    pdf_canvas.showPage()
                
                logger.debug(f"Added page {page_num} to PDF")
                
            except Exception as e:
                page_num = self.pages[img_idx]
                logger.error(f"Failed to add page {page_num} to PDF: {e}")
                logger.debug(f"Image data length: {len(img_data)}, First 20 bytes: {img_data[:20]}")
        
        pdf_canvas.save()
        
        logger.info(f"PDF created with {len(valid_images)} pages: {output_file}")
        return output_file
    
    def _print_progress(self):
        """Print progress statistics"""
        logger.info(f"\nProgress: {self.stats['downloaded']}/{self.stats['total_pages']} "
                   f"(Failed: {self.stats['failed']}, Skipped: {self.stats['skipped']})")
    
    def _cleanup(self):
        """Cleanup resources"""
        if self.client:
            self.client.close()
        
        http_stats = self.client.get_stats() if self.client else {}
        
        logger.info("\n" + "=" * 60)
        logger.info("EXTRACTION COMPLETE")
        logger.info("=" * 60)
        logger.info(f"Total pages: {self.stats['total_pages']}")
        logger.info(f"Downloaded: {self.stats['downloaded']}")
        logger.info(f"Failed: {self.stats['failed']}")
        logger.info(f"Skipped: {self.stats['skipped']}")
        logger.info(f"Retried successfully: {self.stats['retried']}")
        if http_stats:
            logger.info(f"\nHTTP Stats:")
            logger.info(f"  Total requests: {http_stats['total_requests']}")
            logger.info(f"  Successful: {http_stats['successful']}")
            logger.info(f"  Gateway errors (502/503): {http_stats['gateway_errors']}")
            logger.info(f"  Timeouts: {http_stats['timeouts']}")
        logger.info("=" * 60)


def extract_web_pages(config: WebExtractionConfig) -> Path:
    """
    Extract paginated content from web API and create PDF
    
    Args:
        config: Extraction configuration
    
    Returns:
        Path to output PDF file
    
    Example:
        config = WebExtractionConfig(
            base_url="https://api.example.com/pages",
            pages="1-50",
            output_file=Path("output.pdf"),
            cookies_from_browser="firefox"
        )
        pdf_file = extract_web_pages(config)
    """
    extractor = WebPageExtractor(config)
    return extractor.extract()
