"""
Structured logging utilities for VPEW-AI
Provides JSON-formatted logs for better analysis and monitoring
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional


class StructuredLogger:
    """Enhanced logger with structured JSON output"""
    
    def __init__(self, name: str, log_file: Optional[str] = None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler with structured format
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler with JSON format
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(StructuredFormatter())
            self.logger.addHandler(file_handler)
    
    def info(self, message: str, **kwargs):
        """Log info message with additional structured data"""
        self._log(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message with additional structured data"""
        self._log(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message with additional structured data"""
        self._log(logging.ERROR, message, **kwargs)
    
    def debug(self, message: str, **kwargs):
        """Log debug message with additional structured data"""
        self._log(logging.DEBUG, message, **kwargs)
    
    def _log(self, level: int, message: str, **kwargs):
        """Internal logging method with structured data"""
        if kwargs:
            # Create structured log entry
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'level': logging.getLevelName(level),
                'message': message,
                'data': kwargs
            }
            self.logger.log(level, json.dumps(log_entry))
        else:
            self.logger.log(level, message)


class StructuredFormatter(logging.Formatter):
    """Custom formatter for JSON-structured logs"""
    
    def format(self, record):
        if hasattr(record, 'getMessage'):
            try:
                # Try to parse as JSON first
                json.loads(record.getMessage())
                return record.getMessage()
            except (json.JSONDecodeError, TypeError):
                # Fallback to structured format
                log_entry = {
                    'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                    'level': record.levelname,
                    'logger': record.name,
                    'message': record.getMessage(),
                    'module': record.module,
                    'function': record.funcName,
                    'line': record.lineno
                }
                return json.dumps(log_entry)
        return super().format(record)


# Performance metrics logger
class PerformanceLogger:
    """Logger for performance metrics and timing"""
    
    def __init__(self, structured_logger: StructuredLogger):
        self.logger = structured_logger
        self.metrics = {}
    
    def start_timer(self, operation: str):
        """Start timing an operation"""
        self.metrics[operation] = {
            'start_time': time.time(),
            'start_timestamp': datetime.utcnow().isoformat()
        }
    
    def end_timer(self, operation: str, **additional_data):
        """End timing an operation and log the result"""
        if operation in self.metrics:
            duration = time.time() - self.metrics[operation]['start_time']
            self.logger.info(
                f"Operation completed: {operation}",
                operation=operation,
                duration_ms=round(duration * 1000, 2),
                start_time=self.metrics[operation]['start_timestamp'],
                end_time=datetime.utcnow().isoformat(),
                **additional_data
            )
            del self.metrics[operation]
            return duration
        return None
    
    def log_metric(self, metric_name: str, value: float, **metadata):
        """Log a performance metric"""
        self.logger.info(
            f"Performance metric: {metric_name}",
            metric_name=metric_name,
            value=value,
            timestamp=datetime.utcnow().isoformat(),
            **metadata
        )


# Global instances
_structured_logger = None
_performance_logger = None


def get_structured_logger(name: str) -> StructuredLogger:
    """Get or create a structured logger instance"""
    global _structured_logger
    if _structured_logger is None:
        log_file = Path("logs") / "vpew-structured.log"
        log_file.parent.mkdir(exist_ok=True)
        _structured_logger = StructuredLogger(name, str(log_file))
    return _structured_logger


def get_performance_logger() -> PerformanceLogger:
    """Get or create a performance logger instance"""
    global _performance_logger
    if _performance_logger is None:
        _performance_logger = PerformanceLogger(get_structured_logger("vpew.performance"))
    return _performance_logger
