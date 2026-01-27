"""Logging and audit infrastructure for PDFAutopsy"""

import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict
import hashlib


@dataclass
class AuditLogEntry:
    timestamp: str
    operation: str
    input_file: Optional[str] = None
    output_file: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    result: Optional[str] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CTFAuditLog:
    mode: str = "ctf"
    challenge_id: Optional[str] = None
    flag_format: Optional[str] = None
    operations: List[AuditLogEntry] = field(default_factory=list)
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None
    
    def add_operation(self, entry: AuditLogEntry):
        self.operations.append(entry)
    
    def finalize(self):
        self.end_time = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def save(self, path: Path):
        self.finalize()
        data = self.to_dict()
        data_json = json.dumps(data, indent=2)
        data["hash"] = hashlib.sha256(data_json.encode()).hexdigest()
        
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)


class PDFAutopsyLogger:
    """Centralized logger for PDFAutopsy"""
    
    def __init__(self, name: str = "pdfautopsy", level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(level)
            
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            
            self.logger.addHandler(handler)
    
    def debug(self, message: str, **kwargs):
        self.logger.debug(message, extra=kwargs)
    
    def info(self, message: str, **kwargs):
        self.logger.info(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs):
        self.logger.warning(message, extra=kwargs)
    
    def error(self, message: str, **kwargs):
        self.logger.error(message, extra=kwargs)
    
    def critical(self, message: str, **kwargs):
        self.logger.critical(message, extra=kwargs)
    
    def set_level(self, level: int):
        self.logger.setLevel(level)
        for handler in self.logger.handlers:
            handler.setLevel(level)


_default_logger: Optional[PDFAutopsyLogger] = None


def get_logger(name: str = "pdfautopsy") -> PDFAutopsyLogger:
    """Get or create the default logger"""
    global _default_logger
    if _default_logger is None:
        _default_logger = PDFAutopsyLogger(name)
    return _default_logger


def setup_logger(verbose: bool = False, debug: bool = False) -> PDFAutopsyLogger:
    """Setup logger with appropriate level"""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING
    
    logger = get_logger()
    logger.set_level(level)
    return logger
