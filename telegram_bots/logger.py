#!/usr/bin/env python3
"""
Logging module for EntroSpies project.
Provides comprehensive logging system with persistent log files and rotation.
"""

import os
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Default logs directory
DEFAULT_LOGS_DIR = 'logs'

def setup_logging(logs_dir=DEFAULT_LOGS_DIR):
    """Setup comprehensive logging system with persistent log files."""
    # Create logs directory
    os.makedirs(logs_dir, exist_ok=True)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Session separator for log files
    session_separator = f"\n{'='*80}\n🚀 NEW SESSION STARTED: {datetime.now().isoformat()}\n{'='*80}\n"
    
    # Setup root logger
    logger = logging.getLogger('EntroSpies')
    logger.setLevel(logging.DEBUG)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # File handler - detailed logging with rotation (max 10MB, keep 5 files)
    file_handler = RotatingFileHandler(
        os.path.join(logs_dir, 'message_collector.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    
    # Console handler - simple logging
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Write session separator to main log
    with open(os.path.join(logs_dir, 'message_collector.log'), 'a', encoding='utf-8') as f:
        f.write(session_separator)
    
    # Create compliance logger for audit trail
    compliance_logger = logging.getLogger('EntroSpies.Compliance')
    compliance_logger.setLevel(logging.INFO)
    compliance_logger.handlers.clear()
    
    compliance_handler = RotatingFileHandler(
        os.path.join(logs_dir, 'compliance.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    compliance_handler.setLevel(logging.INFO)
    compliance_handler.setFormatter(detailed_formatter)
    compliance_logger.addHandler(compliance_handler)
    
    # Write session separator to compliance log
    with open(os.path.join(logs_dir, 'compliance.log'), 'a', encoding='utf-8') as f:
        f.write(session_separator)
    
    # Create error logger for critical issues
    error_logger = logging.getLogger('EntroSpies.Errors')
    error_logger.setLevel(logging.ERROR)
    error_logger.handlers.clear()
    
    error_handler = RotatingFileHandler(
        os.path.join(logs_dir, 'errors.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)
    error_logger.addHandler(error_handler)
    
    # Write session separator to error log
    with open(os.path.join(logs_dir, 'errors.log'), 'a', encoding='utf-8') as f:
        f.write(session_separator)
    
    return logger, compliance_logger, error_logger

def get_loggers():
    """Get existing loggers without reconfiguring them."""
    logger = logging.getLogger('EntroSpies')
    compliance_logger = logging.getLogger('EntroSpies.Compliance')
    error_logger = logging.getLogger('EntroSpies.Errors')
    
    return logger, compliance_logger, error_logger