"""Plugin loader and registry"""

import importlib.util
import inspect
import sys
from pathlib import Path
from typing import Dict, List, Optional, Type
from collections import defaultdict

from pdfscalpel.plugins.base import (
    BasePlugin,
    PluginType,
    PluginMetadata,
    AnalyzerPlugin,
    ExtractorPlugin,
    GeneratorPlugin,
    MutatorPlugin,
    SolverPlugin,
    UtilityPlugin,
)
from pdfscalpel.core.logging import get_logger
from pdfscalpel.core.exceptions import PluginError

logger = get_logger()


class PluginRegistry:
    """Central registry for all plugins"""
    
    def __init__(self):
        self._plugins: Dict[str, BasePlugin] = {}
        self._plugins_by_type: Dict[PluginType, List[BasePlugin]] = defaultdict(list)
        self._failed_plugins: Dict[str, str] = {}
    
    def register(self, plugin: BasePlugin) -> bool:
        """
        Register a plugin instance
        
        Args:
            plugin: Plugin instance to register
        
        Returns:
            True if registration successful
        """
        try:
            metadata = plugin.metadata
            
            if metadata.name in self._plugins:
                logger.warning(f"Plugin {metadata.name} already registered, skipping")
                return False
            
            valid, error = plugin.validate_dependencies()
            if not valid:
                logger.error(f"Plugin {metadata.name} dependency check failed: {error}")
                self._failed_plugins[metadata.name] = error
                return False
            
            if not plugin.initialize():
                error = f"Plugin {metadata.name} initialization failed"
                logger.error(error)
                self._failed_plugins[metadata.name] = error
                return False
            
            self._plugins[metadata.name] = plugin
            self._plugins_by_type[metadata.plugin_type].append(plugin)
            
            logger.info(f"Registered plugin: {metadata.name} v{metadata.version} ({metadata.plugin_type.value})")
            return True
            
        except Exception as e:
            error = f"Failed to register plugin: {e}"
            logger.error(error)
            if hasattr(plugin, 'metadata'):
                self._failed_plugins[plugin.metadata.name] = str(e)
            return False
    
    def unregister(self, name: str) -> bool:
        """
        Unregister a plugin by name
        
        Args:
            name: Plugin name
        
        Returns:
            True if unregistration successful
        """
        if name not in self._plugins:
            return False
        
        plugin = self._plugins[name]
        plugin.cleanup()
        
        del self._plugins[name]
        self._plugins_by_type[plugin.metadata.plugin_type].remove(plugin)
        
        logger.info(f"Unregistered plugin: {name}")
        return True
    
    def get(self, name: str) -> Optional[BasePlugin]:
        """Get plugin by name"""
        return self._plugins.get(name)
    
    def get_by_type(self, plugin_type: PluginType) -> List[BasePlugin]:
        """Get all plugins of a specific type"""
        return self._plugins_by_type.get(plugin_type, [])
    
    def list_all(self) -> List[PluginMetadata]:
        """List all registered plugin metadata"""
        return [p.metadata for p in self._plugins.values()]
    
    def list_failed(self) -> Dict[str, str]:
        """List plugins that failed to load"""
        return self._failed_plugins.copy()
    
    def cleanup_all(self):
        """Cleanup all plugins"""
        for plugin in self._plugins.values():
            try:
                plugin.cleanup()
            except Exception as e:
                logger.error(f"Error cleaning up plugin {plugin.metadata.name}: {e}")
        
        self._plugins.clear()
        self._plugins_by_type.clear()
    
    def __len__(self) -> int:
        """Return number of registered plugins"""
        return len(self._plugins)


class PluginLoader:
    """Plugin discovery and loading"""
    
    def __init__(self, registry: PluginRegistry):
        self.registry = registry
    
    def load_from_directory(self, directory: Path, recursive: bool = False) -> int:
        """
        Discover and load plugins from directory
        
        Args:
            directory: Directory to scan
            recursive: Scan subdirectories
        
        Returns:
            Number of plugins successfully loaded
        """
        if not directory.exists():
            logger.warning(f"Plugin directory does not exist: {directory}")
            return 0
        
        if not directory.is_dir():
            logger.error(f"Plugin path is not a directory: {directory}")
            return 0
        
        pattern = "**/*.py" if recursive else "*.py"
        plugin_files = list(directory.glob(pattern))
        
        loaded = 0
        for plugin_file in plugin_files:
            if plugin_file.name.startswith("_"):
                continue
            
            try:
                plugins = self._load_from_file(plugin_file)
                loaded += plugins
            except Exception as e:
                logger.error(f"Error loading plugin file {plugin_file}: {e}")
        
        logger.info(f"Loaded {loaded} plugins from {directory}")
        return loaded
    
    def load_from_file(self, file_path: Path) -> int:
        """
        Load plugins from a specific file
        
        Args:
            file_path: Python file containing plugins
        
        Returns:
            Number of plugins loaded
        """
        if not file_path.exists():
            raise PluginError(f"Plugin file not found: {file_path}")
        
        return self._load_from_file(file_path)
    
    def _load_from_file(self, file_path: Path) -> int:
        """Internal method to load plugins from file"""
        module_name = f"pdfautopsy.plugins.dynamic.{file_path.stem}"
        
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            logger.error(f"Could not load spec for {file_path}")
            return 0
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        
        try:
            spec.loader.exec_module(module)
        except Exception as e:
            logger.error(f"Error executing module {file_path}: {e}")
            return 0
        
        loaded = 0
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BasePlugin) and
                obj is not BasePlugin and
                not inspect.isabstract(obj) and
                obj.__module__ == module_name
            ):
                try:
                    plugin_instance = obj()
                    
                    if not self._validate_plugin(plugin_instance):
                        logger.warning(f"Plugin {name} validation failed in {file_path}")
                        continue
                    
                    if self.registry.register(plugin_instance):
                        loaded += 1
                        
                except Exception as e:
                    logger.error(f"Error instantiating plugin {name} from {file_path}: {e}")
        
        return loaded
    
    def _validate_plugin(self, plugin: BasePlugin) -> bool:
        """
        Validate plugin implementation
        
        Args:
            plugin: Plugin instance to validate
        
        Returns:
            True if plugin is valid
        """
        try:
            metadata = plugin.metadata
            
            if not isinstance(metadata, PluginMetadata):
                logger.error(f"Plugin metadata must be PluginMetadata instance")
                return False
            
            if not metadata.name:
                logger.error(f"Plugin name cannot be empty")
                return False
            
            if not metadata.version:
                logger.error(f"Plugin {metadata.name} must have version")
                return False
            
            if not isinstance(metadata.plugin_type, PluginType):
                logger.error(f"Plugin {metadata.name} must have valid PluginType")
                return False
            
            required_base_classes = {
                PluginType.ANALYZER: AnalyzerPlugin,
                PluginType.EXTRACTOR: ExtractorPlugin,
                PluginType.GENERATOR: GeneratorPlugin,
                PluginType.MUTATOR: MutatorPlugin,
                PluginType.SOLVER: SolverPlugin,
                PluginType.UTILITY: UtilityPlugin,
            }
            
            expected_base = required_base_classes.get(metadata.plugin_type)
            if expected_base and not isinstance(plugin, expected_base):
                logger.error(
                    f"Plugin {metadata.name} type {metadata.plugin_type.value} "
                    f"must inherit from {expected_base.__name__}"
                )
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Plugin validation error: {e}")
            return False


_global_registry: Optional[PluginRegistry] = None
_global_loader: Optional[PluginLoader] = None


def get_registry() -> PluginRegistry:
    """Get global plugin registry (singleton)"""
    global _global_registry
    if _global_registry is None:
        _global_registry = PluginRegistry()
    return _global_registry


def get_loader() -> PluginLoader:
    """Get global plugin loader (singleton)"""
    global _global_loader
    if _global_loader is None:
        _global_loader = PluginLoader(get_registry())
    return _global_loader


def discover_plugins(
    plugin_dirs: Optional[List[Path]] = None,
    recursive: bool = False
) -> int:
    """
    Discover and load plugins from standard locations
    
    Args:
        plugin_dirs: Additional directories to scan (optional)
        recursive: Scan subdirectories
    
    Returns:
        Total number of plugins loaded
    """
    loader = get_loader()
    total_loaded = 0
    
    default_dirs = [
        Path(__file__).parent / "examples",
        Path.home() / ".pdfautopsy" / "plugins",
    ]
    
    if plugin_dirs:
        default_dirs.extend(plugin_dirs)
    
    for plugin_dir in default_dirs:
        if plugin_dir.exists():
            loaded = loader.load_from_directory(plugin_dir, recursive=recursive)
            total_loaded += loaded
    
    return total_loaded
