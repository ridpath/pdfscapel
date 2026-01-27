"""Example analyzer plugin for custom PDF analysis"""

from pdfscalpel.plugins import AnalyzerPlugin, PluginMetadata, PluginType, PluginResult
from pdfscalpel.core.pdf_base import PDFDocument


class CustomMetadataAnalyzer(AnalyzerPlugin):
    """
    Example analyzer plugin that extracts and analyzes custom metadata fields
    """
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="custom-metadata-analyzer",
            version="1.0.0",
            author="PDFAutopsy Team",
            description="Analyzes custom and non-standard metadata fields in PDFs",
            plugin_type=PluginType.ANALYZER,
        )
    
    def analyze(self, pdf: PDFDocument, **options) -> PluginResult:
        """
        Extract and analyze custom metadata fields
        
        Options:
            - include_xmp: Include XMP metadata (default: True)
            - show_all: Show all fields including standard ones (default: False)
        """
        include_xmp = options.get("include_xmp", True)
        show_all = options.get("show_all", False)
        
        results = {
            "custom_fields": {},
            "field_count": 0,
            "has_xmp": False,
            "suspicious_fields": [],
        }
        
        standard_fields = {
            "/Title", "/Author", "/Subject", "/Keywords",
            "/Creator", "/Producer", "/CreationDate", "/ModDate"
        }
        
        if pdf.pdf.trailer.get("/Info"):
            info = pdf.pdf.trailer["/Info"]
            for key in info.keys():
                key_str = str(key)
                
                if not show_all and key_str in standard_fields:
                    continue
                
                value = str(info[key])
                results["custom_fields"][key_str] = value
                results["field_count"] += 1
                
                if self._is_suspicious_field(key_str, value):
                    results["suspicious_fields"].append({
                        "field": key_str,
                        "value": value,
                        "reason": "Non-standard field or unusual content"
                    })
        
        if include_xmp and pdf.pdf.Root.get("/Metadata"):
            results["has_xmp"] = True
        
        return PluginResult(success=True, data=results)
    
    def _is_suspicious_field(self, key: str, value: str) -> bool:
        """Check if a metadata field looks suspicious"""
        suspicious_keywords = ["script", "javascript", "exec", "cmd", "shell"]
        
        key_lower = key.lower()
        value_lower = value.lower()
        
        for keyword in suspicious_keywords:
            if keyword in key_lower or keyword in value_lower:
                return True
        
        return False


class PageComplexityAnalyzer(AnalyzerPlugin):
    """
    Example analyzer plugin that measures page complexity
    """
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="page-complexity-analyzer",
            version="1.0.0",
            author="PDFAutopsy Team",
            description="Analyzes page complexity based on object count and structure",
            plugin_type=PluginType.ANALYZER,
        )
    
    def analyze(self, pdf: PDFDocument, **options) -> PluginResult:
        """
        Analyze complexity of each page
        
        Options:
            - threshold: Complexity threshold for warnings (default: 100)
        """
        threshold = options.get("threshold", 100)
        
        results = {
            "pages": [],
            "total_pages": len(pdf.pdf.pages),
            "complex_pages": [],
            "average_complexity": 0.0,
        }
        
        total_complexity = 0
        
        for i, page in enumerate(pdf.pdf.pages):
            page_num = i + 1
            complexity = self._calculate_complexity(page)
            total_complexity += complexity
            
            page_info = {
                "page": page_num,
                "complexity_score": complexity,
                "object_count": len(list(page.keys())),
            }
            
            results["pages"].append(page_info)
            
            if complexity > threshold:
                results["complex_pages"].append(page_num)
        
        if results["total_pages"] > 0:
            results["average_complexity"] = total_complexity / results["total_pages"]
        
        return PluginResult(success=True, data=results)
    
    def _calculate_complexity(self, page) -> int:
        """Calculate complexity score for a page"""
        score = 0
        
        score += len(list(page.keys())) * 5
        
        if "/Contents" in page:
            contents = page["/Contents"]
            if isinstance(contents, list):
                score += len(contents) * 10
            else:
                score += 10
        
        if "/Annots" in page:
            annots = page["/Annots"]
            if hasattr(annots, "__len__"):
                score += len(annots) * 15
        
        if "/Resources" in page:
            resources = page["/Resources"]
            if "/Font" in resources:
                fonts = resources["/Font"]
                score += len(list(fonts.keys())) * 3
            if "/XObject" in resources:
                xobjects = resources["/XObject"]
                score += len(list(xobjects.keys())) * 8
        
        return score
