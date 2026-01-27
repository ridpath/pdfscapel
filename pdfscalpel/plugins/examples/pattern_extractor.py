"""Example extractor plugin for pattern-based extraction"""

import re
from pathlib import Path

from pdfscalpel.plugins import ExtractorPlugin, PluginMetadata, PluginType, PluginResult
from pdfscalpel.core.pdf_base import PDFDocument


class EmailExtractor(ExtractorPlugin):
    """
    Example extractor plugin that finds and extracts all email addresses
    """
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="email-extractor",
            version="1.0.0",
            author="PDFAutopsy Team",
            description="Extracts all email addresses from PDF text content",
            plugin_type=PluginType.EXTRACTOR,
        )
    
    def extract(self, pdf: PDFDocument, output_dir: Path, **options) -> PluginResult:
        """
        Extract all email addresses
        
        Options:
            - save_file: Save results to file (default: True)
            - unique_only: Only save unique emails (default: True)
        """
        save_file = options.get("save_file", True)
        unique_only = options.get("unique_only", True)
        
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        emails = []
        for page_num, page in enumerate(pdf.pdf.pages, 1):
            try:
                if "/Contents" in page:
                    contents = page["/Contents"]
                    if hasattr(contents, "read_bytes"):
                        text = contents.read_bytes().decode("latin-1", errors="ignore")
                        found = re.findall(email_pattern, text)
                        
                        for email in found:
                            emails.append({
                                "email": email,
                                "page": page_num,
                            })
            except Exception:
                continue
        
        if unique_only:
            seen = set()
            unique_emails = []
            for item in emails:
                if item["email"] not in seen:
                    seen.add(item["email"])
                    unique_emails.append(item)
            emails = unique_emails
        
        results = {
            "total_found": len(emails),
            "emails": emails,
        }
        
        if save_file and emails:
            output_file = output_dir / "extracted_emails.txt"
            with open(output_file, "w") as f:
                for item in emails:
                    f.write(f"{item['email']} (page {item['page']})\n")
            results["output_file"] = str(output_file)
        
        return PluginResult(success=True, data=results)


class URLExtractor(ExtractorPlugin):
    """
    Example extractor plugin that finds and extracts all URLs
    """
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="url-extractor",
            version="1.0.0",
            author="PDFAutopsy Team",
            description="Extracts all URLs from PDF content and annotations",
            plugin_type=PluginType.EXTRACTOR,
        )
    
    def extract(self, pdf: PDFDocument, output_dir: Path, **options) -> PluginResult:
        """
        Extract all URLs
        
        Options:
            - include_annotations: Extract URLs from annotations (default: True)
            - save_file: Save results to file (default: True)
        """
        include_annotations = options.get("include_annotations", True)
        save_file = options.get("save_file", True)
        
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        
        urls = []
        
        for page_num, page in enumerate(pdf.pdf.pages, 1):
            try:
                if "/Contents" in page:
                    contents = page["/Contents"]
                    if hasattr(contents, "read_bytes"):
                        text = contents.read_bytes().decode("latin-1", errors="ignore")
                        found = re.findall(url_pattern, text)
                        
                        for url in found:
                            urls.append({
                                "url": url,
                                "page": page_num,
                                "source": "content",
                            })
                
                if include_annotations and "/Annots" in page:
                    annots = page["/Annots"]
                    for annot in annots:
                        if "/A" in annot and "/URI" in annot["/A"]:
                            uri = str(annot["/A"]["/URI"])
                            urls.append({
                                "url": uri,
                                "page": page_num,
                                "source": "annotation",
                            })
            except Exception:
                continue
        
        seen = set()
        unique_urls = []
        for item in urls:
            if item["url"] not in seen:
                seen.add(item["url"])
                unique_urls.append(item)
        
        results = {
            "total_found": len(unique_urls),
            "urls": unique_urls,
        }
        
        if save_file and unique_urls:
            output_file = output_dir / "extracted_urls.txt"
            with open(output_file, "w") as f:
                for item in unique_urls:
                    f.write(f"{item['url']} (page {item['page']}, {item['source']})\n")
            results["output_file"] = str(output_file)
        
        return PluginResult(success=True, data=results)
