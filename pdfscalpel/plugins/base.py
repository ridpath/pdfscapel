"""Base plugin system for PDFAutopsy extensibility"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from pdfscalpel.core.pdf_base import PDFDocument
from pdfscalpel.core.logging import get_logger

logger = get_logger()


class PluginType(Enum):
    """Plugin categories"""
    ANALYZER = "analyzer"
    EXTRACTOR = "extractor"
    GENERATOR = "generator"
    MUTATOR = "mutator"
    SOLVER = "solver"
    UTILITY = "utility"


@dataclass
class PluginMetadata:
    """Plugin metadata"""
    name: str
    version: str
    author: str
    description: str
    plugin_type: PluginType
    dependencies: List[str] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []


class PluginResult:
    """Base class for plugin execution results"""
    
    def __init__(self, success: bool, data: Any = None, error: Optional[str] = None):
        self.success = success
        self.data = data
        self.error = error
    
    def __repr__(self):
        if self.success:
            return f"PluginResult(success=True, data={self.data})"
        return f"PluginResult(success=False, error={self.error})"


class BasePlugin(ABC):
    """Abstract base class for all plugins"""
    
    def __init__(self):
        self._initialized = False
        self._metadata: Optional[PluginMetadata] = None
    
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        pass
    
    def initialize(self) -> bool:
        """
        Initialize plugin (called once after loading)
        Override to add custom initialization logic
        Returns True if successful
        """
        logger.debug(f"Initializing plugin: {self.metadata.name}")
        self._initialized = True
        return True
    
    def cleanup(self):
        """
        Cleanup plugin resources
        Override to add custom cleanup logic
        """
        logger.debug(f"Cleaning up plugin: {self.metadata.name}")
        self._initialized = False
    
    @abstractmethod
    def execute(self, *args, **kwargs) -> PluginResult:
        """
        Execute plugin logic
        Must be implemented by subclasses
        """
        pass
    
    def validate_dependencies(self) -> tuple[bool, Optional[str]]:
        """
        Check if all plugin dependencies are available
        Returns (success, error_message)
        """
        if not self.metadata.dependencies:
            return True, None
        
        missing = []
        for dep in self.metadata.dependencies:
            try:
                __import__(dep)
            except ImportError:
                missing.append(dep)
        
        if missing:
            return False, f"Missing dependencies: {', '.join(missing)}"
        return True, None
    
    @property
    def is_initialized(self) -> bool:
        """Check if plugin is initialized"""
        return self._initialized


class AnalyzerPlugin(BasePlugin):
    """Base class for analysis plugins"""
    
    @abstractmethod
    def analyze(self, pdf: PDFDocument, **options) -> PluginResult:
        """
        Analyze PDF and return findings
        
        Args:
            pdf: PDFDocument to analyze
            **options: Analysis options
        
        Returns:
            PluginResult with analysis data
        """
        pass
    
    def execute(self, pdf: PDFDocument, **options) -> PluginResult:
        """Execute analyzer"""
        try:
            return self.analyze(pdf, **options)
        except Exception as e:
            logger.error(f"Analyzer plugin {self.metadata.name} failed: {e}")
            return PluginResult(success=False, error=str(e))


class ExtractorPlugin(BasePlugin):
    """Base class for extraction plugins"""
    
    @abstractmethod
    def extract(self, pdf: PDFDocument, output_dir: Path, **options) -> PluginResult:
        """
        Extract data from PDF
        
        Args:
            pdf: PDFDocument to extract from
            output_dir: Directory for extracted data
            **options: Extraction options
        
        Returns:
            PluginResult with extracted data info
        """
        pass
    
    def execute(self, pdf: PDFDocument, output_dir: Path, **options) -> PluginResult:
        """Execute extractor"""
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            return self.extract(pdf, output_dir, **options)
        except Exception as e:
            logger.error(f"Extractor plugin {self.metadata.name} failed: {e}")
            return PluginResult(success=False, error=str(e))


class GeneratorPlugin(BasePlugin):
    """Base class for PDF generation plugins"""
    
    @abstractmethod
    def generate(self, output_path: Path, **options) -> PluginResult:
        """
        Generate PDF or PDF component
        
        Args:
            output_path: Output file path
            **options: Generation options
        
        Returns:
            PluginResult with generation info
        """
        pass
    
    def execute(self, output_path: Path, **options) -> PluginResult:
        """Execute generator"""
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            return self.generate(output_path, **options)
        except Exception as e:
            logger.error(f"Generator plugin {self.metadata.name} failed: {e}")
            return PluginResult(success=False, error=str(e))


class MutatorPlugin(BasePlugin):
    """Base class for PDF mutation plugins"""
    
    @abstractmethod
    def mutate(self, pdf: PDFDocument, output_path: Path, **options) -> PluginResult:
        """
        Mutate PDF and save to output
        
        Args:
            pdf: PDFDocument to mutate
            output_path: Output file path
            **options: Mutation options
        
        Returns:
            PluginResult with mutation info
        """
        pass
    
    def execute(self, pdf: PDFDocument, output_path: Path, **options) -> PluginResult:
        """Execute mutator"""
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            return self.mutate(pdf, output_path, **options)
        except Exception as e:
            logger.error(f"Mutator plugin {self.metadata.name} failed: {e}")
            return PluginResult(success=False, error=str(e))


class SolverPlugin(BasePlugin):
    """Base class for CTF solver plugins"""
    
    @abstractmethod
    def solve(self, pdf: PDFDocument, **options) -> PluginResult:
        """
        Attempt to solve CTF challenge
        
        Args:
            pdf: PDFDocument to solve
            **options: Solver options
        
        Returns:
            PluginResult with solution data
        """
        pass
    
    def execute(self, pdf: PDFDocument, **options) -> PluginResult:
        """Execute solver"""
        try:
            return self.solve(pdf, **options)
        except Exception as e:
            logger.error(f"Solver plugin {self.metadata.name} failed: {e}")
            return PluginResult(success=False, error=str(e))


class UtilityPlugin(BasePlugin):
    """Base class for utility plugins (custom workflows)"""
    
    @abstractmethod
    def run(self, **options) -> PluginResult:
        """
        Run utility function
        
        Args:
            **options: Utility options
        
        Returns:
            PluginResult with execution info
        """
        pass
    
    def execute(self, **options) -> PluginResult:
        """Execute utility"""
        try:
            return self.run(**options)
        except Exception as e:
            logger.error(f"Utility plugin {self.metadata.name} failed: {e}")
            return PluginResult(success=False, error=str(e))
