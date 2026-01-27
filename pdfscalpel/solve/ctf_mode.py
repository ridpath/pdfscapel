"""CTF Mode enforcement and audit trail system"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Any, Dict
from contextlib import contextmanager

from ..core.logging import CTFAuditLog, AuditLogEntry, get_logger
from ..core.exceptions import PDFScalpelError

logger = get_logger(__name__)


class CTFModeError(PDFScalpelError):
    """Raised when CTF mode contract is violated"""
    pass


class CTFModeContext:
    """
    Context manager for CTF mode operations
    
    Enforces ethical CTF boundaries by:
    - Requiring challenge ID
    - Logging all operations
    - Generating signed provenance files
    - Preventing destructive operations without logging
    """
    
    def __init__(
        self,
        challenge_id: Optional[str] = None,
        flag_format: Optional[str] = None,
        operation_name: str = "unknown",
        require_challenge_id: bool = True,
        audit_log_path: Optional[Path] = None,
    ):
        """
        Initialize CTF mode context
        
        Args:
            challenge_id: Unique identifier for the CTF challenge
            flag_format: Expected flag format (e.g., "CTF{...}")
            operation_name: Name of the operation being performed
            require_challenge_id: Whether to enforce challenge ID requirement
            audit_log_path: Path to save audit log (default: ctf_audit_{timestamp}.json)
        """
        self.challenge_id = challenge_id
        self.flag_format = flag_format
        self.operation_name = operation_name
        self.require_challenge_id = require_challenge_id
        self.audit_log_path = audit_log_path
        
        self.audit_log = CTFAuditLog(
            mode="ctf",
            challenge_id=challenge_id,
            flag_format=flag_format
        )
        
        self._validate()
    
    def _validate(self):
        """Validate CTF mode contract"""
        if self.require_challenge_id and not self.challenge_id:
            raise CTFModeError(
                "CTF mode requires a challenge ID. "
                "Use --challenge-id to specify the challenge you are working on. "
                "This ensures accountability and ethical use."
            )
        
        if self.challenge_id and len(self.challenge_id.strip()) < 3:
            raise CTFModeError(
                "Challenge ID must be at least 3 characters long. "
                "Please provide a meaningful identifier."
            )
    
    def log_operation(
        self,
        operation: str,
        input_file: Optional[str] = None,
        output_file: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        result: Optional[str] = None,
        error: Optional[str] = None,
    ):
        """
        Log an operation in the audit trail
        
        Args:
            operation: Name of the operation
            input_file: Input file path
            output_file: Output file path
            parameters: Operation parameters
            result: Operation result
            error: Error message if operation failed
        """
        entry = AuditLogEntry(
            timestamp=datetime.now().isoformat(),
            operation=operation,
            input_file=input_file,
            output_file=output_file,
            parameters=parameters or {},
            result=result,
            error=error
        )
        
        self.audit_log.add_operation(entry)
        
        if logger:
            logger.info(
                f"CTF Operation: {operation}",
                challenge_id=self.challenge_id,
                input=input_file,
                output=output_file
            )
    
    def save_provenance(self, path: Optional[Path] = None) -> Path:
        """
        Save audit log with signed provenance
        
        Args:
            path: Custom path for audit log (optional)
        
        Returns:
            Path where audit log was saved
        """
        if path is None:
            if self.audit_log_path:
                path = self.audit_log_path
            else:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                challenge = self.challenge_id or "unknown"
                filename = f"ctf_audit_{challenge}_{timestamp}.json"
                path = Path.cwd() / filename
        
        self.audit_log.save(path)
        logger.info(f"CTF audit log saved: {path}")
        
        return path
    
    def __enter__(self):
        """Enter CTF mode context"""
        logger.info(
            f"Entering CTF mode: {self.operation_name}",
            challenge_id=self.challenge_id
        )
        self.log_operation(
            operation="ctf_mode_start",
            parameters={"operation": self.operation_name}
        )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit CTF mode context and save audit log"""
        if exc_type is not None:
            self.log_operation(
                operation="ctf_mode_error",
                error=str(exc_val),
                parameters={"exception_type": exc_type.__name__}
            )
        
        self.log_operation(
            operation="ctf_mode_end",
            result="success" if exc_type is None else "error"
        )
        
        try:
            path = self.save_provenance()
            logger.info(f"CTF mode complete. Audit log: {path}")
        except Exception as e:
            logger.error(f"Failed to save audit log: {e}")
        
        return False


@contextmanager
def ctf_mode(
    challenge_id: Optional[str] = None,
    flag_format: Optional[str] = None,
    operation_name: str = "solve",
    require_challenge_id: bool = True,
    audit_log_path: Optional[Path] = None,
):
    """
    Context manager for CTF mode operations
    
    Usage:
        with ctf_mode(challenge_id="ctf2024-pdf1") as ctx:
            ctx.log_operation("password_attempt", parameters={"method": "dictionary"})
            # Perform operations
            ctx.log_operation("password_found", result="success")
    
    Args:
        challenge_id: Unique identifier for the CTF challenge
        flag_format: Expected flag format
        operation_name: Name of the operation
        require_challenge_id: Whether to enforce challenge ID
        audit_log_path: Custom audit log path
    
    Yields:
        CTFModeContext instance for logging operations
    
    Raises:
        CTFModeError: If CTF mode contract is violated
    """
    ctx = CTFModeContext(
        challenge_id=challenge_id,
        flag_format=flag_format,
        operation_name=operation_name,
        require_challenge_id=require_challenge_id,
        audit_log_path=audit_log_path
    )
    
    with ctx:
        yield ctx


def validate_ctf_mode(ctf_mode_enabled: bool, challenge_id: Optional[str] = None):
    """
    Validate CTF mode requirements for a destructive operation
    
    Args:
        ctf_mode_enabled: Whether CTF mode is enabled
        challenge_id: Challenge ID if provided
    
    Raises:
        CTFModeError: If CTF mode requirements are not met
    """
    if not ctf_mode_enabled:
        raise CTFModeError(
            "This operation requires CTF mode. "
            "Use --ctf-mode to enable ethical CTF solving. "
            "CTF mode enforces accountability through audit trails."
        )
    
    if not challenge_id:
        logger.warning(
            "No challenge ID provided. "
            "Best practice: use --challenge-id to identify the challenge."
        )


def generate_provenance_file(
    challenge_id: str,
    operations: list,
    output_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Generate a signed provenance file for CTF operations
    
    Args:
        challenge_id: Challenge identifier
        operations: List of operations performed
        output_path: Path to save provenance file
    
    Returns:
        Provenance data with signature
    """
    provenance = {
        "mode": "ctf",
        "challenge_id": challenge_id,
        "operations": operations,
        "timestamp": datetime.now().isoformat(),
    }
    
    data_json = json.dumps(provenance, indent=2, sort_keys=True)
    signature = hashlib.sha256(data_json.encode()).hexdigest()
    
    provenance["signature"] = signature
    
    if output_path:
        with open(output_path, 'w') as f:
            json.dump(provenance, f, indent=2)
    
    return provenance


def verify_provenance_file(provenance_path: Path) -> bool:
    """
    Verify the integrity of a provenance file
    
    Args:
        provenance_path: Path to provenance file
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        with open(provenance_path, 'r') as f:
            data = json.load(f)
        
        stored_signature = data.pop("signature", None)
        if not stored_signature:
            logger.warning("No signature found in provenance file")
            return False
        
        data_json = json.dumps(data, indent=2, sort_keys=True)
        computed_signature = hashlib.sha256(data_json.encode()).hexdigest()
        
        if stored_signature == computed_signature:
            logger.info("Provenance signature verified")
            return True
        else:
            logger.error("Provenance signature mismatch")
            return False
    
    except Exception as e:
        logger.error(f"Failed to verify provenance: {e}")
        return False
