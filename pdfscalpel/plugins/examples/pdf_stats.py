"""Example utility plugin for PDF statistics"""

from pathlib import Path
from collections import Counter

from pdfscalpel.plugins import UtilityPlugin, PluginMetadata, PluginType, PluginResult
from pdfscalpel.core.pdf_base import PDFDocument


class PDFStatisticsGenerator(UtilityPlugin):
    """
    Example utility plugin that generates comprehensive PDF statistics
    """
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="pdf-statistics",
            version="1.0.0",
            author="PDFAutopsy Team",
            description="Generates comprehensive statistics about PDF structure and content",
            plugin_type=PluginType.UTILITY,
        )
    
    def run(self, **options) -> PluginResult:
        """
        Generate PDF statistics
        
        Options:
            - pdf_path: Path to PDF file (required)
            - output_file: Path to save statistics (optional)
            - include_objects: Include detailed object statistics (default: True)
        """
        pdf_path = options.get("pdf_path")
        if not pdf_path:
            return PluginResult(success=False, error="pdf_path is required")
        
        pdf_path = Path(pdf_path)
        if not pdf_path.exists():
            return PluginResult(success=False, error=f"PDF not found: {pdf_path}")
        
        output_file = options.get("output_file")
        include_objects = options.get("include_objects", True)
        
        try:
            with PDFDocument.open(pdf_path) as pdf:
                stats = self._generate_statistics(pdf, include_objects)
        except Exception as e:
            return PluginResult(success=False, error=f"Failed to analyze PDF: {e}")
        
        if output_file:
            self._save_statistics(stats, Path(output_file))
            stats["output_file"] = str(output_file)
        
        return PluginResult(success=True, data=stats)
    
    def _generate_statistics(self, pdf: PDFDocument, include_objects: bool) -> dict:
        """Generate comprehensive PDF statistics"""
        stats = {
            "file": {
                "path": str(pdf.path),
                "size_bytes": pdf.path.stat().st_size,
                "size_human": self._format_size(pdf.path.stat().st_size),
            },
            "structure": {
                "version": str(pdf.pdf.pdf_version) if hasattr(pdf.pdf, "pdf_version") else "Unknown",
                "page_count": len(pdf.pdf.pages),
                "is_encrypted": pdf.pdf.is_encrypted if hasattr(pdf.pdf, "is_encrypted") else False,
                "is_linearized": "/Linearized" in pdf.pdf.Root if hasattr(pdf.pdf, "Root") else False,
            },
            "content": {
                "has_javascript": False,
                "has_attachments": False,
                "has_forms": False,
                "annotation_count": 0,
            },
        }
        
        annotation_count = 0
        for page in pdf.pdf.pages:
            if "/Annots" in page:
                annots = page["/Annots"]
                annotation_count += len(annots) if hasattr(annots, "__len__") else 1
        stats["content"]["annotation_count"] = annotation_count
        
        if pdf.pdf.Root:
            root = pdf.pdf.Root
            
            if "/AcroForm" in root:
                stats["content"]["has_forms"] = True
            
            if "/Names" in root:
                names = root["/Names"]
                if "/EmbeddedFiles" in names:
                    stats["content"]["has_attachments"] = True
                if "/JavaScript" in names:
                    stats["content"]["has_javascript"] = True
        
        if include_objects:
            stats["objects"] = self._analyze_objects(pdf)
        
        return stats
    
    def _analyze_objects(self, pdf: PDFDocument) -> dict:
        """Analyze PDF objects"""
        object_types = Counter()
        stream_count = 0
        total_objects = 0
        
        for obj in pdf.pdf.objects:
            total_objects += 1
            
            if hasattr(obj, "stream_dict"):
                stream_count += 1
                if "/Filter" in obj.stream_dict:
                    filter_type = str(obj.stream_dict["/Filter"])
                    object_types[filter_type] += 1
            
            obj_type = type(obj).__name__
            object_types[obj_type] += 1
        
        return {
            "total_objects": total_objects,
            "stream_count": stream_count,
            "type_breakdown": dict(object_types.most_common(10)),
        }
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
    
    def _save_statistics(self, stats: dict, output_file: Path):
        """Save statistics to file"""
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w") as f:
            f.write("PDF Statistics Report\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("File Information:\n")
            f.write(f"  Path: {stats['file']['path']}\n")
            f.write(f"  Size: {stats['file']['size_human']} ({stats['file']['size_bytes']:,} bytes)\n\n")
            
            f.write("Structure:\n")
            f.write(f"  PDF Version: {stats['structure']['version']}\n")
            f.write(f"  Pages: {stats['structure']['page_count']}\n")
            f.write(f"  Encrypted: {stats['structure']['is_encrypted']}\n")
            f.write(f"  Linearized: {stats['structure']['is_linearized']}\n\n")
            
            f.write("Content:\n")
            f.write(f"  JavaScript: {stats['content']['has_javascript']}\n")
            f.write(f"  Attachments: {stats['content']['has_attachments']}\n")
            f.write(f"  Forms: {stats['content']['has_forms']}\n")
            f.write(f"  Annotations: {stats['content']['annotation_count']}\n\n")
            
            if "objects" in stats:
                f.write("Objects:\n")
                f.write(f"  Total Objects: {stats['objects']['total_objects']}\n")
                f.write(f"  Streams: {stats['objects']['stream_count']}\n")
                f.write(f"  Type Breakdown (top 10):\n")
                for obj_type, count in stats['objects']['type_breakdown'].items():
                    f.write(f"    {obj_type}: {count}\n")
