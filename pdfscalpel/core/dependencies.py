"""Dependency checking with graceful degradation"""

import os
import sys
import platform
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from pdfscalpel.core.constants import EXTERNAL_TOOLS, PYTHON_PACKAGES
from pdfscalpel.core.logging import get_logger

logger = get_logger()


@dataclass
class DependencyStatus:
    name: str
    available: bool
    version: Optional[str] = None
    path: Optional[str] = None
    error: Optional[str] = None


def detect_os() -> str:
    """Detect operating system type"""
    system = platform.system().lower()
    
    if system == "windows":
        return "windows"
    elif system == "linux":
        if "microsoft" in platform.release().lower() or "wsl" in platform.release().lower():
            return "wsl"
        return "linux"
    elif system == "darwin":
        return "macos"
    else:
        return "unknown"


def check_python_package(package_name: str, import_name: Optional[str] = None) -> DependencyStatus:
    """Check if a Python package is available"""
    import_name = import_name or package_name
    
    try:
        module = __import__(import_name)
        version = getattr(module, '__version__', None)
        return DependencyStatus(
            name=package_name,
            available=True,
            version=version,
        )
    except ImportError as e:
        return DependencyStatus(
            name=package_name,
            available=False,
            error=str(e),
        )


def find_executable_windows(command: str, search_paths: List[str]) -> Optional[str]:
    """Find executable on Windows, including in custom paths"""
    import glob
    
    for search_path in search_paths:
        for pattern_path in glob.glob(search_path):
            if Path(pattern_path).exists():
                exe_path = Path(pattern_path) / f"{command}.exe"
                if exe_path.exists():
                    parent_dir = str(exe_path.parent)
                    if parent_dir not in os.environ['PATH']:
                        os.environ['PATH'] = parent_dir + os.pathsep + os.environ['PATH']
                    return str(exe_path)
    
    import shutil
    return shutil.which(command)


def check_external_tool(tool_key: str) -> DependencyStatus:
    """Check if an external tool is available"""
    tool_info = EXTERNAL_TOOLS.get(tool_key, {})
    command = tool_info.get("command", tool_key)
    check_args = tool_info.get("check_args", ["--version"])
    
    os_type = detect_os()
    
    exe_path = None
    if os_type == "windows" and "windows_paths" in tool_info:
        exe_path = find_executable_windows(command, tool_info["windows_paths"])
    else:
        import shutil
        exe_path = shutil.which(command)
    
    if not exe_path:
        return DependencyStatus(
            name=tool_info.get("name", tool_key),
            available=False,
            error=f"Command '{command}' not found in PATH",
        )
    
    try:
        result = subprocess.run(
            [exe_path] + check_args,
            capture_output=True,
            text=True,
            timeout=5,
        )
        
        version = None
        if result.returncode == 0:
            output = result.stdout + result.stderr
            lines = output.split('\n')
            if lines:
                version = lines[0].strip()
        
        return DependencyStatus(
            name=tool_info.get("name", tool_key),
            available=True,
            version=version,
            path=exe_path,
        )
    except subprocess.TimeoutExpired:
        return DependencyStatus(
            name=tool_info.get("name", tool_key),
            available=False,
            error="Command timed out",
        )
    except Exception as e:
        return DependencyStatus(
            name=tool_info.get("name", tool_key),
            available=False,
            error=str(e),
        )


def check_all_dependencies(verbose: bool = False) -> Dict[str, DependencyStatus]:
    """Check all dependencies and return status"""
    results = {}
    
    if verbose:
        logger.info("Checking Python packages...")
    
    for pkg_key, pkg_info in PYTHON_PACKAGES.items():
        import_name = pkg_info.get("import_name", pkg_key)
        status = check_python_package(pkg_key, import_name)
        results[f"py:{pkg_key}"] = status
        
        if verbose:
            if status.available:
                version_str = f" ({status.version})" if status.version else ""
                logger.info(f"  [OK] {pkg_info['name']}{version_str}")
            else:
                if pkg_info.get("required"):
                    logger.error(f"  [MISSING] {pkg_info['name']} (REQUIRED)")
                else:
                    logger.warning(f"  [MISSING] {pkg_info['name']} (optional)")
    
    if verbose:
        logger.info("Checking external tools...")
    
    for tool_key in EXTERNAL_TOOLS.keys():
        status = check_external_tool(tool_key)
        results[f"tool:{tool_key}"] = status
        
        if verbose:
            if status.available:
                version_str = f" ({status.version})" if status.version else ""
                logger.info(f"  [OK] {status.name}{version_str}")
            else:
                logger.warning(f"  [MISSING] {status.name} (optional)")
    
    return results


def get_install_instructions(dependency: str) -> Optional[str]:
    """Get installation instructions for a dependency"""
    os_type = detect_os()
    
    if dependency.startswith("py:"):
        pkg_key = dependency[3:]
        pkg_info = PYTHON_PACKAGES.get(pkg_key)
        if pkg_info:
            return pkg_info.get("install")
    
    elif dependency.startswith("tool:"):
        tool_key = dependency[5:]
        tool_info = EXTERNAL_TOOLS.get(tool_key)
        if tool_info and "install" in tool_info:
            return tool_info["install"].get(os_type, tool_info["install"].get("linux"))
    
    return None


def print_missing_dependencies(results: Dict[str, DependencyStatus]):
    """Print missing dependencies with install instructions"""
    os_type = detect_os()
    
    missing_required = []
    missing_optional = []
    
    for dep_key, status in results.items():
        if not status.available:
            if dep_key.startswith("py:"):
                pkg_key = dep_key[3:]
                pkg_info = PYTHON_PACKAGES.get(pkg_key, {})
                if pkg_info.get("required"):
                    missing_required.append((dep_key, status))
                else:
                    missing_optional.append((dep_key, status))
            else:
                missing_optional.append((dep_key, status))
    
    if missing_required:
        print("\nMISSING REQUIRED DEPENDENCIES:")
        print("=" * 60)
        for dep_key, status in missing_required:
            print(f"\n{status.name}")
            install = get_install_instructions(dep_key)
            if install:
                print(f"  Install: {install}")
        print("\nPlease install required dependencies before using PDFAutopsy.")
        return False
    
    if missing_optional:
        print("\nOPTIONAL DEPENDENCIES NOT FOUND:")
        print("=" * 60)
        print("These are not required but enable additional features.\n")
        
        for dep_key, status in missing_optional:
            print(f"{status.name}")
            
            if dep_key.startswith("py:"):
                pkg_key = dep_key[3:]
                pkg_info = PYTHON_PACKAGES.get(pkg_key, {})
                features = pkg_info.get("features", [])
                if features:
                    print(f"  Features: {', '.join(features)}")
            
            install = get_install_instructions(dep_key)
            if install:
                print(f"  Install: {install}")
            print()
    
    return True


def require_dependency(dependency: str, feature: str = "this feature"):
    """Raise error if dependency is not available"""
    from pdfscalpel.core.exceptions import DependencyMissingError
    
    status = None
    if dependency.startswith("py:"):
        pkg_key = dependency[3:]
        pkg_info = PYTHON_PACKAGES.get(pkg_key, {})
        import_name = pkg_info.get("import_name", pkg_key)
        status = check_python_package(pkg_key, import_name)
    elif dependency.startswith("tool:"):
        tool_key = dependency[5:]
        status = check_external_tool(tool_key)
    
    if status and not status.available:
        install_hint = get_install_instructions(dependency)
        raise DependencyMissingError(
            dependency=status.name,
            install_hint=f"{feature} requires {status.name}.\n{install_hint}" if install_hint else None
        )
