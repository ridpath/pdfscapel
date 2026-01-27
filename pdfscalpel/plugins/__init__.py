"""Plugin system for PDFAutopsy"""

from pdfscalpel.plugins.base import (
    BasePlugin,
    PluginType,
    PluginMetadata,
    PluginResult,
    AnalyzerPlugin,
    ExtractorPlugin,
    GeneratorPlugin,
    MutatorPlugin,
    SolverPlugin,
    UtilityPlugin,
)

from pdfscalpel.plugins.loader import (
    PluginRegistry,
    PluginLoader,
    get_registry,
    get_loader,
    discover_plugins,
)

__all__ = [
    "BasePlugin",
    "PluginType",
    "PluginMetadata",
    "PluginResult",
    "AnalyzerPlugin",
    "ExtractorPlugin",
    "GeneratorPlugin",
    "MutatorPlugin",
    "SolverPlugin",
    "UtilityPlugin",
    "PluginRegistry",
    "PluginLoader",
    "get_registry",
    "get_loader",
    "discover_plugins",
]
