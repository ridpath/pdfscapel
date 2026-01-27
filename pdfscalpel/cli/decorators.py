"""CLI decorators for error handling and common patterns"""

import functools
import sys
from pathlib import Path
from typing import Callable, Optional

import click

from pdfscalpel.core.exceptions import PDFScalpelError
from pdfscalpel.core.error_handler import explain_error, ErrorContext
from pdfscalpel.cli.ui import (
    print_success,
    print_error,
    print_verbose,
    print_debug,
    OperationTimer,
)
from pdfscalpel.core.logging import get_logger


def handle_errors(operation_name: Optional[str] = None):
    """
    Decorator to handle errors with enhanced error reporting
    
    Usage:
        @handle_errors("Analyzing watermark")
        def analyze_watermark_cmd(input_pdf, ...):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            ctx = click.get_current_context()
            config = ctx.obj.get('config') if ctx.obj else None
            
            show_traceback = config.debug if config else False
            operation = operation_name or func.__name__.replace('_', ' ').title()
            
            input_file = kwargs.get('input_pdf') or kwargs.get('input')
            output_file = kwargs.get('output_pdf') or kwargs.get('output')
            
            error_context = ErrorContext(
                operation=operation,
                input_file=input_file,
                output_file=output_file,
            )
            
            try:
                return func(*args, **kwargs)
            except PDFScalpelError as e:
                explain_error(e, error_context, show_traceback)
                sys.exit(1)
            except KeyboardInterrupt:
                print_error("Operation cancelled by user")
                sys.exit(130)
            except Exception as e:
                if show_traceback:
                    raise
                else:
                    print_error(f"Unexpected error: {e}")
                    print_error("Use --debug for full traceback")
                    sys.exit(1)
        
        return wrapper
    return decorator


def with_timing(show_start: bool = True):
    """
    Decorator to time operations
    
    Usage:
        @with_timing()
        def some_command(...):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            operation = func.__name__.replace('_cmd', '').replace('_', ' ').title()
            
            with OperationTimer(operation, show_start=show_start):
                return func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_input_file(param_name: str = 'input_pdf'):
    """
    Decorator to validate input file exists
    
    Usage:
        @require_input_file('input_pdf')
        def process_cmd(input_pdf, ...):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            input_path = kwargs.get(param_name)
            
            if not input_path:
                print_error(f"Input file parameter '{param_name}' is required")
                sys.exit(1)
            
            if not Path(input_path).exists():
                print_error(f"Input file does not exist: {input_path}")
                sys.exit(1)
            
            if not Path(input_path).is_file():
                print_error(f"Input path is not a file: {input_path}")
                sys.exit(1)
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def log_command(func: Callable) -> Callable:
    """
    Decorator to log command execution
    
    Usage:
        @log_command
        def some_command(...):
            ...
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_logger()
        ctx = click.get_current_context()
        
        command_path = ctx.command_path
        params = {k: v for k, v in kwargs.items() if v is not None}
        
        logger.info(f"Executing command: {command_path}")
        logger.debug(f"Parameters: {params}")
        
        result = func(*args, **kwargs)
        
        logger.info(f"Command completed: {command_path}")
        
        return result
    
    return wrapper


def verbose_option(func: Callable) -> Callable:
    """
    Add verbose mode support to command
    
    Usage:
        @verbose_option
        def some_command(verbose, ...):
            print_verbose("Details", verbose)
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        ctx = click.get_current_context()
        config = ctx.obj.get('config') if ctx.obj else None
        
        verbose = kwargs.get('verbose', False)
        if config:
            verbose = verbose or config.verbose
        
        kwargs['verbose'] = verbose
        
        return func(*args, **kwargs)
    
    return wrapper


def debug_option(func: Callable) -> Callable:
    """
    Add debug mode support to command
    
    Usage:
        @debug_option
        def some_command(debug, ...):
            print_debug("Debug info", debug)
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        ctx = click.get_current_context()
        config = ctx.obj.get('config') if ctx.obj else None
        
        debug = kwargs.get('debug', False)
        if config:
            debug = debug or config.debug
        
        kwargs['debug'] = debug
        
        return func(*args, **kwargs)
    
    return wrapper
