"""Custom exception hierarchy for PDFScalpel"""


class PDFScalpelError(Exception):
    """Base exception for all PDFScalpel errors"""
    pass


class PDFOpenError(PDFScalpelError):
    """Raised when a PDF file cannot be opened"""
    
    def __init__(self, message="PDF file cannot be opened", path=None, reason=None):
        if path:
            message = f"{message}: {path}"
        if reason:
            message = f"{message} ({reason})"
        super().__init__(message)
        self.path = path
        self.reason = reason


class PDFEncryptedError(PDFScalpelError):
    """Raised when a PDF is encrypted and no password provided"""
    
    def __init__(self, message="PDF is encrypted", algorithm=None, details=None):
        super().__init__(message)
        self.algorithm = algorithm
        self.details = details or {}


class PDFCorruptedError(PDFScalpelError):
    """Raised when a PDF file is corrupted or malformed"""
    
    def __init__(self, message="PDF is corrupted", corruption_type=None, details=None):
        super().__init__(message)
        self.corruption_type = corruption_type
        self.details = details or {}


class PDFNotFoundError(PDFScalpelError):
    """Raised when a PDF file is not found"""
    pass


class DependencyMissingError(PDFScalpelError):
    """Raised when a required dependency is missing"""
    
    def __init__(self, dependency, install_hint=None):
        message = f"Missing dependency: {dependency}"
        if install_hint:
            message += f"\n{install_hint}"
        super().__init__(message)
        self.dependency = dependency
        self.install_hint = install_hint


class ConfigurationError(PDFScalpelError):
    """Raised when configuration is invalid"""
    pass


class ValidationError(PDFScalpelError):
    """Raised when input validation fails"""
    pass


class OperationNotSupportedError(PDFScalpelError):
    """Raised when an operation is not supported on this PDF"""
    pass


class ExternalToolError(PDFScalpelError):
    """Raised when an external tool fails"""
    
    def __init__(self, tool, message, returncode=None, stderr=None):
        super().__init__(f"{tool} failed: {message}")
        self.tool = tool
        self.returncode = returncode
        self.stderr = stderr


class PluginError(PDFScalpelError):
    """Raised when a plugin operation fails"""
    pass
