#!/usr/bin/env python3
"""
Parsing Failure Logger Module for EntroSpies project.
Tracks and logs messages that cannot be parsed by infostealer parsers.
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List, Union
from logging.handlers import RotatingFileHandler

class ParsingFailureLogger:
    """
    Logger for tracking parsing failures across all infostealer components.
    Maintains structured logs of messages that cannot be parsed for various reasons.
    """
    
    def __init__(self, logs_dir: str = "logs", logger: Optional[logging.Logger] = None):
        """
        Initialize the parsing failure logger.
        
        Args:
            logs_dir: Directory to store failure logs
            logger: Optional parent logger for debugging
        """
        self.logs_dir = Path(logs_dir)
        self.logs_dir.mkdir(exist_ok=True)
        
        self.logger = logger or logging.getLogger(__name__)
        
        # Create dedicated failure log file
        self.failure_log_path = self.logs_dir / "failed_parsing_message.log"
        
        # Setup rotating file handler for failure logs
        self.failure_handler = RotatingFileHandler(
            self.failure_log_path,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        
        # Create failure-specific logger
        self.failure_logger = logging.getLogger('EntroSpies.ParsingFailures')
        self.failure_logger.setLevel(logging.INFO)
        self.failure_logger.handlers.clear()
        
        # Custom formatter for failure logs
        failure_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        self.failure_handler.setFormatter(failure_formatter)
        self.failure_logger.addHandler(self.failure_handler)
        
        # Categories of parsing failures
        self.failure_categories = {
            'PASSWORD_EXTRACTION': 'Password could not be extracted from message',
            'ARCHIVE_DECOMPRESSION': 'Archive could not be decompressed',
            'ARCHIVE_WRONG_PASSWORD': 'Archive has wrong password',
            'LOG_PARSING': 'Log files could not be parsed',
            'WORKFLOW_ORCHESTRATION': 'Workflow processing failed',
            'FORMAT_UNSUPPORTED': 'File format not supported',
            'FILE_ACCESS': 'File could not be accessed or read',
            'VALIDATION_FAILED': 'Extracted data failed validation',
            'PARSER_ERROR': 'Parser encountered an error',
            'TIMEOUT': 'Processing timeout occurred',
            'NO_CREDENTIALS_FOUND': 'No credentials found in decompressed folder',
            'UNKNOWN': 'Unknown parsing failure'
        }
        
        # Write session separator to failure log
        session_separator = f"\n{'='*80}\n🚨 NEW PARSING FAILURE SESSION: {datetime.now().isoformat()}\n{'='*80}\n"
        with open(self.failure_log_path, 'a', encoding='utf-8') as f:
            f.write(session_separator)
        
        self.logger.info(f"Parsing failure logger initialized: {self.failure_log_path}")
    
    def log_failure(self, 
                   message_file_path: Union[str, Path],
                   failure_category: str,
                   failure_reason: str,
                   channel_name: Optional[str] = None,
                   message_id: Optional[int] = None,
                   error_details: Optional[Dict[str, Any]] = None,
                   additional_context: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a parsing failure with structured information.
        
        Args:
            message_file_path: Path to the message file that failed parsing
            failure_category: Category of failure (see self.failure_categories)
            failure_reason: Detailed reason for the failure
            channel_name: Name of the channel (if available)
            message_id: Telegram message ID (if available)
            error_details: Additional error information
            additional_context: Extra context information
        """
        try:
            # Ensure category is valid
            if failure_category not in self.failure_categories:
                self.logger.warning(f"Unknown failure category: {failure_category}, using 'UNKNOWN'")
                failure_category = 'UNKNOWN'
            
            # Create structured failure record
            failure_record = {
                'timestamp': datetime.now().isoformat(),
                'message_file_path': str(message_file_path),
                'failure_category': failure_category,
                'failure_description': self.failure_categories[failure_category],
                'failure_reason': failure_reason,
                'channel_name': channel_name or 'unknown',
                'message_id': message_id or 0,
                'error_details': error_details or {},
                'additional_context': additional_context or {}
            }
            
            # Log to failure log file
            log_message = self._format_failure_message(failure_record)
            self.failure_logger.info(log_message)
            
            # Also log to main logger for debugging
            self.logger.debug(f"Parsing failure logged: {failure_category} - {message_file_path}")
            
        except Exception as e:
            self.logger.error(f"Error logging parsing failure: {e}")
    
    def log_password_extraction_failure(self, 
                                       message_file_path: Union[str, Path],
                                       message_text: str,
                                       channel_name: Optional[str] = None,
                                       message_id: Optional[int] = None,
                                       patterns_tried: Optional[List[str]] = None) -> None:
        """
        Log a password extraction failure.
        
        Args:
            message_file_path: Path to the message file
            message_text: The message text that failed password extraction
            channel_name: Channel name
            message_id: Message ID
            patterns_tried: List of patterns that were tried
        """
        error_details = {
            'message_text_length': len(message_text) if message_text else 0,
            'message_preview': message_text[:100] if message_text else '',
            'patterns_tried': patterns_tried or []
        }
        
        self.log_failure(
            message_file_path=message_file_path,
            failure_category='PASSWORD_EXTRACTION',
            failure_reason='No password patterns matched in message text',
            channel_name=channel_name,
            message_id=message_id,
            error_details=error_details
        )
    
    def log_archive_decompression_failure(self,
                                         message_file_path: Union[str, Path],
                                         archive_path: Union[str, Path],
                                         password_used: Optional[str] = None,
                                         error_message: Optional[str] = None,
                                         channel_name: Optional[str] = None,
                                         message_id: Optional[int] = None,
                                         failure_type: Optional[str] = None) -> None:
        """
        Log an archive decompression failure.
        
        Args:
            message_file_path: Path to the message file
            archive_path: Path to the archive that failed
            password_used: Password that was used (if any)
            error_message: Error message from decompression attempt
            channel_name: Channel name
            message_id: Message ID
            failure_type: Type of failure (e.g., 'wrong_password', 'extraction_failure')
        """
        error_details = {
            'archive_path': str(archive_path),
            'password_provided': password_used is not None,
            'error_message': error_message or 'Unknown decompression error',
            'failure_type': failure_type or 'unknown_failure'
        }
        
        # Use more specific failure category for wrong password
        if failure_type == 'wrong_password':
            category = 'ARCHIVE_WRONG_PASSWORD'
            reason = f'Wrong password for archive: {Path(archive_path).name}'
        else:
            category = 'ARCHIVE_DECOMPRESSION'
            reason = f'Failed to decompress archive: {Path(archive_path).name}'
        
        self.log_failure(
            message_file_path=message_file_path,
            failure_category=category,
            failure_reason=reason,
            channel_name=channel_name,
            message_id=message_id,
            error_details=error_details
        )
    
    def log_log_parsing_failure(self,
                               message_file_path: Union[str, Path],
                               log_file_path: Union[str, Path],
                               parser_name: str,
                               error_message: Optional[str] = None,
                               channel_name: Optional[str] = None,
                               message_id: Optional[int] = None) -> None:
        """
        Log a log file parsing failure.
        
        Args:
            message_file_path: Path to the message file
            log_file_path: Path to the log file that failed parsing
            parser_name: Name of the parser that failed
            error_message: Error message from parsing attempt
            channel_name: Channel name
            message_id: Message ID
        """
        error_details = {
            'log_file_path': str(log_file_path),
            'parser_name': parser_name,
            'error_message': error_message or 'Unknown parsing error'
        }
        
        self.log_failure(
            message_file_path=message_file_path,
            failure_category='LOG_PARSING',
            failure_reason=f'Failed to parse log file with {parser_name}',
            channel_name=channel_name,
            message_id=message_id,
            error_details=error_details
        )
    
    def log_workflow_failure(self,
                            message_file_path: Union[str, Path],
                            workflow_step: str,
                            error_message: str,
                            channel_name: Optional[str] = None,
                            message_id: Optional[int] = None,
                            workflow_context: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a workflow orchestration failure.
        
        Args:
            message_file_path: Path to the message file
            workflow_step: Step in workflow that failed
            error_message: Error message from workflow
            channel_name: Channel name
            message_id: Message ID
            workflow_context: Additional workflow context
        """
        error_details = {
            'workflow_step': workflow_step,
            'error_message': error_message,
            'workflow_context': workflow_context or {}
        }
        
        self.log_failure(
            message_file_path=message_file_path,
            failure_category='WORKFLOW_ORCHESTRATION',
            failure_reason=f'Workflow failed at step: {workflow_step}',
            channel_name=channel_name,
            message_id=message_id,
            error_details=error_details
        )
    
    def log_format_unsupported_failure(self,
                                      message_file_path: Union[str, Path],
                                      file_path: Union[str, Path],
                                      file_format: str,
                                      channel_name: Optional[str] = None,
                                      message_id: Optional[int] = None) -> None:
        """
        Log an unsupported file format failure.
        
        Args:
            message_file_path: Path to the message file
            file_path: Path to the unsupported file
            file_format: Format that is not supported
            channel_name: Channel name
            message_id: Message ID
        """
        error_details = {
            'unsupported_file_path': str(file_path),
            'file_format': file_format,
            'file_extension': Path(file_path).suffix
        }
        
        self.log_failure(
            message_file_path=message_file_path,
            failure_category='FORMAT_UNSUPPORTED',
            failure_reason=f'Unsupported file format: {file_format}',
            channel_name=channel_name,
            message_id=message_id,
            error_details=error_details
        )
    
    def log_no_credentials_found(self,
                                message_file_path: Union[str, Path],
                                extract_dir: Union[str, Path],
                                total_files: int,
                                file_types: Dict[str, int],
                                analysis_details: Dict[str, Any],
                                channel_name: Optional[str] = None,
                                message_id: Optional[int] = None) -> None:
        """
        Log when no credentials are found in decompressed folder.
        This may indicate parser failure or empty/invalid files.
        
        Args:
            message_file_path: Path to the message file
            extract_dir: Directory that was analyzed
            total_files: Total number of files in extracted directory
            file_types: Dictionary of file extensions and their counts
            analysis_details: Detailed analysis results
            channel_name: Channel name
            message_id: Message ID
        """
        error_details = {
            'extract_directory': str(extract_dir),
            'total_files': total_files,
            'file_types': file_types,
            'credential_files_found': analysis_details.get('credential_files_found', 0),
            'log_files_processed': analysis_details.get('log_files_processed', 0),
            'files_analyzed': analysis_details.get('files_analyzed', 0),
            'analysis_method': analysis_details.get('analysis_method', 'unknown'),
            'potential_parser_failure': total_files > 0 and analysis_details.get('credential_files_found', 0) == 0
        }
        
        # Determine failure reason based on analysis
        if total_files == 0:
            failure_reason = "No files found in decompressed folder"
        elif analysis_details.get('credential_files_found', 0) == 0:
            failure_reason = f"No credential files detected in {total_files} files (potential parser failure)"
        else:
            failure_reason = f"Credential files found but no credentials extracted from {analysis_details.get('credential_files_found', 0)} files"
        
        self.log_failure(
            message_file_path=message_file_path,
            failure_category='NO_CREDENTIALS_FOUND',
            failure_reason=failure_reason,
            channel_name=channel_name,
            message_id=message_id,
            error_details=error_details
        )
    
    def get_failure_statistics(self) -> Dict[str, Any]:
        """
        Analyze failure log and return statistics.
        
        Returns:
            Dictionary with failure statistics
        """
        stats = {
            'total_failures': 0,
            'failures_by_category': {category: 0 for category in self.failure_categories.keys()},
            'failures_by_channel': {},
            'recent_failures': [],
            'log_file_size': 0
        }
        
        try:
            if not self.failure_log_path.exists():
                return stats
            
            stats['log_file_size'] = self.failure_log_path.stat().st_size
            
            # Read and analyze failure log
            with open(self.failure_log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('='):
                    continue
                
                # Parse log line for failure information
                if ' - INFO - ' in line:
                    stats['total_failures'] += 1
                    
                    # Extract category and channel if possible
                    for category in self.failure_categories.keys():
                        if f'[{category}]' in line:
                            stats['failures_by_category'][category] += 1
                            break
                    
                    # Extract channel name if present
                    if 'Channel:' in line:
                        try:
                            channel_part = line.split('Channel:')[1].split(',')[0].strip()
                            if channel_part not in stats['failures_by_channel']:
                                stats['failures_by_channel'][channel_part] = 0
                            stats['failures_by_channel'][channel_part] += 1
                        except (IndexError, AttributeError):
                            pass
                    
                    # Keep recent failures (last 10)
                    if len(stats['recent_failures']) < 10:
                        stats['recent_failures'].append(line)
            
        except Exception as e:
            self.logger.error(f"Error analyzing failure statistics: {e}")
        
        return stats
    
    def _format_failure_message(self, failure_record: Dict[str, Any]) -> str:
        """
        Format a failure record for logging.
        
        Args:
            failure_record: Dictionary with failure information
            
        Returns:
            Formatted log message
        """
        message_parts = [
            f"[{failure_record['failure_category']}]",
            f"File: {failure_record['message_file_path']}",
            f"Channel: {failure_record['channel_name']}",
            f"Message ID: {failure_record['message_id']}",
            f"Reason: {failure_record['failure_reason']}"
        ]
        
        # Add error details if present
        if failure_record['error_details']:
            details_str = json.dumps(failure_record['error_details'], separators=(',', ':'))
            message_parts.append(f"Details: {details_str}")
        
        # Add additional context if present
        if failure_record['additional_context']:
            context_str = json.dumps(failure_record['additional_context'], separators=(',', ':'))
            message_parts.append(f"Context: {context_str}")
        
        return " | ".join(message_parts)
    
    def cleanup_old_logs(self, max_age_days: int = 30) -> None:
        """
        Clean up old failure logs.
        
        Args:
            max_age_days: Maximum age of logs to keep in days
        """
        try:
            # This is handled by RotatingFileHandler, but we could add additional cleanup here
            # For now, just log that cleanup was requested
            self.logger.info(f"Failure log cleanup requested for logs older than {max_age_days} days")
        except Exception as e:
            self.logger.error(f"Error during failure log cleanup: {e}")


def main():
    """
    Command-line interface for testing the parsing failure logger.
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Test parsing failure logger')
    parser.add_argument('--stats', action='store_true', help='Show failure statistics')
    parser.add_argument('--test', action='store_true', help='Log test failures')
    parser.add_argument('--logs-dir', default='logs', help='Logs directory')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    
    # Create failure logger
    failure_logger = ParsingFailureLogger(logs_dir=args.logs_dir)
    
    if args.test:
        # Log some test failures
        print("Logging test failures...")
        failure_logger.log_password_extraction_failure(
            message_file_path="/test/msg_123/message.json",
            message_text="Test message without password",
            channel_name="test_channel",
            message_id=123
        )
        
        failure_logger.log_archive_decompression_failure(
            message_file_path="/test/msg_456/message.json",
            archive_path="/test/msg_456/archive.zip",
            password_used="wrong_password",
            error_message="Wrong password",
            channel_name="test_channel",
            message_id=456
        )
        
        print("Test failures logged successfully")
    
    if args.stats:
        # Show failure statistics
        stats = failure_logger.get_failure_statistics()
        print("\nFailure Statistics:")
        print("=" * 50)
        print(f"Total Failures: {stats['total_failures']}")
        print(f"Log File Size: {stats['log_file_size']} bytes")
        print("\nFailures by Category:")
        for category, count in stats['failures_by_category'].items():
            if count > 0:
                print(f"  {category}: {count}")
        
        if stats['failures_by_channel']:
            print("\nFailures by Channel:")
            for channel, count in stats['failures_by_channel'].items():
                print(f"  {channel}: {count}")
        
        if stats['recent_failures']:
            print(f"\nRecent Failures ({len(stats['recent_failures'])}):")
            for failure in stats['recent_failures']:
                print(f"  {failure}")


if __name__ == "__main__":
    main()