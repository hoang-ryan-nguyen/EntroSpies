#!/usr/bin/env python3
"""
Boxed.pw Log Parser Module for EntroSpies project.
Handles parsing of extracted log files from .boxed.pw channel for credential extraction.
"""

import os
import json
import logging
import re
import csv
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any
try:
    from parsing_failure_logger import ParsingFailureLogger
except ImportError:
    # Try importing from project root
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from parsing_failure_logger import ParsingFailureLogger


class BoxedPwLogParser:
    """
    Parser for extracting credentials from .boxed.pw log files.
    Handles various log formats including JSON, CSV, and text files.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None, max_file_size: int = None,
                 failure_logger: Optional[ParsingFailureLogger] = None):
        """
        Initialize the boxed.pw log parser.
        
        Args:
            logger: Optional logger instance
            max_file_size: Maximum file size to process (defaults to 100MB)
            failure_logger: Optional failure logger for tracking parsing failures
        """
        self.logger = logger or logging.getLogger(__name__)
        self.max_file_size = max_file_size or int(os.getenv('MAX_EXTRACTION_SIZE', 100 * 1024 * 1024))
        self.failure_logger = failure_logger
        
        # File type patterns for log identification
        self.log_extensions = {'.txt', '.log', '.csv', '.json'}
        self.log_keywords = ['password', 'login', 'credential', 'browser', 'cookie', 'history']
        
        self.logger.info("Boxed.pw log parser initialized")
    
    def find_log_files(self, extract_dir: Path, extracted_files: List[str]) -> List[Path]:
        """
        Find log files in extracted archive.
        Includes traditional log files and credential dump files.
        
        Args:
            extract_dir: Directory containing extracted files
            extracted_files: List of extracted file paths
            
        Returns:
            List of log file paths
        """
        log_files = []
        
        try:
            for file_path in extracted_files:
                full_path = extract_dir / file_path
                
                if full_path.exists() and full_path.is_file():
                    file_name_lower = full_path.name.lower()
                    
                    # Check extension
                    if full_path.suffix.lower() in self.log_extensions:
                        log_files.append(full_path)
                        continue
                    
                    # Check filename for keywords
                    if any(keyword in file_name_lower for keyword in self.log_keywords):
                        log_files.append(full_path)
                        continue
                    
                    # Check for credential dump files (like STARLINK file)
                    if self._is_credential_dump_file(full_path):
                        log_files.append(full_path)
                        continue
            
            self.logger.info(f"Found {len(log_files)} log files to parse")
            
        except Exception as e:
            self.logger.error(f"Error finding log files: {e}")
        
        return log_files
    
    def _is_credential_dump_file(self, file_path: Path) -> bool:
        """
        Check if a file appears to be a credential dump file.
        
        Args:
            file_path: Path to file to check
            
        Returns:
            True if file appears to be a credential dump
        """
        try:
            file_name_lower = file_path.name.lower()
            
            # Check for common credential dump file patterns
            credential_indicators = [
                'starlink', 'combo', 'combolist', 'leak', 'breach', 'dump', 'creds', 'credentials',
                'passwords', 'logins', 'accounts', 'database', 'db', 'stealer', 'logs',
                'redline', 'vidar', 'raccoon', 'azorult', 'lokibot', 'formbook'
            ]
            
            # Check filename for credential indicators
            if any(indicator in file_name_lower for indicator in credential_indicators):
                # Additional check: peek at file content to confirm it contains credential-like data
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        sample_content = f.read(2048)  # Read first 2KB
                    
                    # Look for patterns that suggest credentials
                    lines = sample_content.split('\n')[:20]  # Check first 20 lines
                    credential_lines = 0
                    
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        
                        # Count lines that look like credentials
                        colon_count = line.count(':')
                        if colon_count >= 2:
                            credential_lines += 1
                    
                    # If more than 20% of sample lines look like credentials, consider it a credential dump
                    if credential_lines > 0 and credential_lines / len(lines) > 0.2:
                        self.logger.debug(f"Detected credential dump file: {file_path.name}")
                        return True
                        
                except Exception:
                    # If we can't read the file, fall back to filename-based detection
                    pass
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking credential dump file {file_path}: {e}")
            return False
    
    def parse_single_log_file(self, log_file: Path, message_file_path: Optional[str] = None,
                             channel_name: Optional[str] = None, message_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Parse a single log file for credentials.
        
        Args:
            log_file: Path to log file
            message_file_path: Path to message file (for failure logging)
            channel_name: Channel name (for failure logging)
            message_id: Message ID (for failure logging)
            
        Returns:
            Dictionary with parsing results
        """
        result = {
            'file_path': str(log_file),
            'file_size': 0,
            'credentials_count': 0,
            'parsing_successful': False,
            'file_type': 'unknown',
            'credentials': []
        }
        
        try:
            if not log_file.exists():
                # Log file access failure
                if self.failure_logger and message_file_path:
                    self.failure_logger.log_log_parsing_failure(
                        message_file_path=message_file_path,
                        log_file_path=log_file,
                        parser_name="boxedpw_log_parser",
                        error_message="Log file not found",
                        channel_name=channel_name,
                        message_id=message_id
                    )
                return result
            
            result['file_size'] = log_file.stat().st_size
            
            # Skip very large files
            if result['file_size'] > self.max_file_size:
                self.logger.warning(f"Skipping large file: {log_file} ({result['file_size']} bytes)")
                # Log as unsupported format (too large)
                if self.failure_logger and message_file_path:
                    self.failure_logger.log_format_unsupported_failure(
                        message_file_path=message_file_path,
                        file_path=log_file,
                        file_format=f"large_file_{result['file_size']}_bytes",
                        channel_name=channel_name,
                        message_id=message_id
                    )
                return result
            
            # Determine file type and parse accordingly
            if log_file.suffix.lower() == '.json':
                result['file_type'] = 'json'
                credentials = self._parse_json_log(log_file)
            elif log_file.suffix.lower() == '.csv':
                result['file_type'] = 'csv'
                credentials = self._parse_csv_log(log_file)
            else:
                result['file_type'] = 'text'
                credentials = self._parse_text_log(log_file)
            
            result['credentials'] = credentials or []
            result['credentials_count'] = len(result['credentials'])
            result['parsing_successful'] = True
            
            if result['credentials_count'] > 0:
                self.logger.info(f"Found {result['credentials_count']} credentials in {log_file}")
            else:
                # Log parsing failure if no credentials found
                if self.failure_logger and message_file_path:
                    self.failure_logger.log_log_parsing_failure(
                        message_file_path=message_file_path,
                        log_file_path=log_file,
                        parser_name="boxedpw_log_parser",
                        error_message="No credentials found in log file",
                        channel_name=channel_name,
                        message_id=message_id
                    )
            
        except Exception as e:
            self.logger.error(f"Error parsing log file {log_file}: {e}")
            
            # Log parsing failure
            if self.failure_logger and message_file_path:
                self.failure_logger.log_log_parsing_failure(
                    message_file_path=message_file_path,
                    log_file_path=log_file,
                    parser_name="boxedpw_log_parser",
                    error_message=str(e),
                    channel_name=channel_name,
                    message_id=message_id
                )
        
        return result
    
    def parse_extracted_logs(self, extract_dir: Path, extracted_files: List[str],
                            message_file_path: Optional[str] = None, channel_name: Optional[str] = None,
                            message_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Parse all extracted log files for credentials and useful information.
        
        Args:
            extract_dir: Directory containing extracted files
            extracted_files: List of extracted file paths
            message_file_path: Path to message file (for failure logging)
            channel_name: Channel name (for failure logging)
            message_id: Message ID (for failure logging)
            
        Returns:
            Dictionary with comprehensive parsing results
        """
        parsing_result = {
            'log_files_processed': 0,
            'total_files': len(extracted_files),
            'credentials_found': 0,
            'parsing_errors': [],
            'file_types': {},
            'summary': {},
            'parsed_files': []
        }
        
        try:
            self.logger.info(f"Parsing {len(extracted_files)} extracted files")
            
            # Analyze file types
            for file_path in extracted_files:
                full_path = extract_dir / file_path
                if full_path.exists() and full_path.is_file():
                    file_ext = full_path.suffix.lower()
                    parsing_result['file_types'][file_ext] = parsing_result['file_types'].get(file_ext, 0) + 1
            
            # Look for log files to parse
            log_files = self.find_log_files(extract_dir, extracted_files)
            parsing_result['log_files_processed'] = len(log_files)
            
            if log_files:
                # Parse each log file
                for log_file in log_files:
                    try:
                        log_result = self.parse_single_log_file(log_file, message_file_path, channel_name, message_id)
                        parsing_result['credentials_found'] += log_result.get('credentials_count', 0)
                        parsing_result['parsed_files'].append(log_result)
                    except Exception as e:
                        parsing_result['parsing_errors'].append(f"Error parsing {log_file}: {str(e)}")
                        self.logger.error(f"Error parsing log file {log_file}: {e}")
            
            # Generate summary
            parsing_result['summary'] = {
                'total_files': len(extracted_files),
                'log_files_found': len(log_files),
                'file_types': list(parsing_result['file_types'].keys()),
                'credentials_found': parsing_result['credentials_found'] > 0,
                'total_credentials': parsing_result['credentials_found']
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing extracted logs: {e}")
            parsing_result['parsing_errors'].append(f"General parsing error: {str(e)}")
        
        return parsing_result
    
    def find_credential_files(self, extract_dir: Path, extracted_files: List[str]) -> List[Path]:
        """
        Find credential files (like "All Passwords.txt") in extracted archive.
        
        Args:
            extract_dir: Directory containing extracted files
            extracted_files: List of extracted file paths
            
        Returns:
            List of credential file paths
        """
        credential_files = []
        
        try:
            # Common credential file names
            credential_filenames = ['All Passwords.txt', 'passwords.txt', 'Password.txt', 'AllPasswords.txt']
            
            for file_path in extracted_files:
                full_path = extract_dir / file_path
                
                if full_path.exists() and full_path.is_file():
                    # Check if filename matches credential file patterns
                    if full_path.name in credential_filenames:
                        credential_files.append(full_path)
                        self.logger.debug(f"Found credential file: {full_path}")
            
            self.logger.info(f"Found {len(credential_files)} credential files")
            
        except Exception as e:
            self.logger.error(f"Error finding credential files: {e}")
        
        return credential_files
    
    def extract_country_code(self, file_path: str) -> str:
        """
        Extract country code from folder path using regex pattern [CC].
        
        Args:
            file_path: Path to extract country code from
            
        Returns:
            Country code or 'unknown'
        """
        try:
            # Use regex to find pattern [CC] where CC is a 2-letter country code
            pattern = r'\[([A-Z]{2})\]'
            match = re.search(pattern, file_path)
            
            if match:
                country_code = match.group(1)
                self.logger.debug(f"Extracted country code '{country_code}' from path: {file_path}")
                return country_code
            else:
                self.logger.debug(f"No country code found in path: {file_path}")
                return 'unknown'
                
        except Exception as e:
            self.logger.warning(f"Error extracting country code from path {file_path}: {e}")
            return 'unknown'
    
    def get_channel_info_from_message_json(self, credential_file_path: Path) -> Dict[str, str]:
        """
        Find the corresponding message JSON file and extract channel information.
        
        Args:
            credential_file_path: Path to the credential file
            
        Returns:
            Dictionary with channel information
        """
        try:
            # Navigate up to find the date directory
            current_dir = credential_file_path.parent
            
            # Keep going up until we find a directory with message JSON files
            while current_dir and current_dir != current_dir.parent:
                json_files = list(current_dir.glob('*_message.json'))
                if json_files:
                    # Use the first message JSON file (they should all be from the same channel)
                    with open(json_files[0], 'r', encoding='utf-8') as f:
                        message_data = json.load(f)
                        
                        # Extract channel info from message data
                        channel_info = message_data.get('channel_info', {})
                        if not channel_info:
                            # Try alternative field names
                            channel_info = {
                                'title': message_data.get('channel', 'unknown'),
                                'username': message_data.get('channel_username', ''),
                                'id': message_data.get('channel_id', 0)
                            }
                        
                        return {
                            'channel_name': channel_info.get('title', 'unknown'),
                            'channel_username': channel_info.get('username', ''),
                            'channel_id': channel_info.get('id', 0),
                            'message_id': message_data.get('message_id', 0)
                        }
                
                current_dir = current_dir.parent
                
        except Exception as e:
            self.logger.warning(f"Could not extract channel info from message JSON: {e}")
            
        return {
            'channel_name': 'unknown',
            'channel_username': '',
            'channel_id': 0,
            'message_id': 0
        }
    
    def parse_credentials_file(self, credential_file: Path) -> List[Dict[str, str]]:
        """
        Parse a credential file for individual credentials.
        Supports both traditional format (SOFT:/URL:/USER:/PASS:) and colon-separated format (url:username:password).
        
        Args:
            credential_file: Path to credential file
            
        Returns:
            List of parsed credential dictionaries
        """
        credentials = []
        
        try:
            with open(credential_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Get file metadata
            file_timestamp = datetime.fromtimestamp(credential_file.stat().st_mtime).isoformat()
            
            # Get channel info from message JSON
            channel_info = self.get_channel_info_from_message_json(credential_file)
            
            # Extract country code from folder path
            country_code = self.extract_country_code(str(credential_file))
            
            # Determine file format and parse accordingly
            if self._is_colon_separated_format(content):
                # Parse colon-separated format (url:username:password)
                self.logger.debug(f"Parsing {credential_file.name} as colon-separated credentials")
                colon_credentials = self._parse_colon_separated_credentials(content)
                
                # Add metadata to each credential
                for credential in colon_credentials:
                    credential['timestamp'] = file_timestamp
                    credential['source_file'] = str(credential_file)
                    credential['channel'] = channel_info['channel_name']
                    credential['channel_username'] = channel_info['channel_username']
                    credential['channel_id'] = channel_info['channel_id']
                    credential['message_id'] = channel_info['message_id']
                    credential['country_code'] = country_code
                    credentials.append(credential)
                    
            else:
                # Parse traditional format (SOFT:/URL:/USER:/PASS:)
                self.logger.debug(f"Parsing {credential_file.name} as traditional credentials")
                credentials.extend(self._parse_traditional_credentials(content, file_timestamp, channel_info, country_code, credential_file))
                    
        except Exception as e:
            self.logger.error(f"Error parsing credential file {credential_file}: {e}")
            
        return credentials
    
    def _is_colon_separated_format(self, content: str) -> bool:
        """
        Determine if the content is in colon-separated format.
        
        Args:
            content: File content to analyze
            
        Returns:
            True if content appears to be colon-separated credentials
        """
        lines = content.strip().split('\n')
        
        # Count lines that look like colon-separated credentials
        colon_lines = 0
        traditional_lines = 0
        total_lines = 0
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//') or line.startswith('-'):
                continue
                
            # Skip header/banner lines
            if any(keyword in line.lower() for keyword in ['join telegram', 'clouds', 'url:login:pass', 'logs']):
                continue
            
            # Skip starlink banner lines but not actual credential lines
            if 'starlink' in line.lower() and ('telegram' in line.lower() or 'join' in line.lower() or line.startswith('|')):
                continue
            
            total_lines += 1
            
            # Check for traditional format indicators
            if any(line.startswith(prefix) for prefix in ['SOFT:', 'URL:', 'USER:', 'PASS:']):
                traditional_lines += 1
                continue
            
            # Check for colon-separated format
            colon_count = line.count(':')
            if colon_count >= 2:
                # Simple heuristic: if it has >= 2 colons and doesn't look like traditional format
                colon_lines += 1
        
        if total_lines == 0:
            return False
        
        # If more than 50% of lines look like colon-separated, assume that format
        colon_ratio = colon_lines / total_lines
        traditional_ratio = traditional_lines / total_lines
        
        self.logger.debug(f"Format detection: {colon_lines} colon-separated lines, {traditional_lines} traditional lines, {total_lines} total lines")
        
        return colon_ratio > 0.5 and colon_ratio > traditional_ratio
    
    def _parse_traditional_credentials(self, content: str, file_timestamp: str, channel_info: Dict[str, str], 
                                     country_code: str, credential_file: Path) -> List[Dict[str, str]]:
        """
        Parse traditional format credentials (SOFT:/URL:/USER:/PASS:).
        
        Args:
            content: File content
            file_timestamp: File timestamp
            channel_info: Channel information
            country_code: Country code
            credential_file: Path to credential file
            
        Returns:
            List of parsed credential dictionaries
        """
        credentials = []
        
        # Split by double newlines to separate credential entries
        entries = content.split('\n\n')
        
        for entry in entries:
            if not entry.strip():
                continue
                
            credential = {}
            lines = entry.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                if line.startswith('SOFT:'):
                    credential['software'] = line[5:].strip()
                elif line.startswith('URL:'):
                    credential['url'] = line[4:].strip()
                elif line.startswith('USER:'):
                    credential['username'] = line[5:].strip()
                elif line.startswith('PASS:'):
                    credential['password'] = line[5:].strip()
            
            # Only add if we have all required fields
            if all(key in credential for key in ['software', 'url', 'username', 'password']):
                credential['timestamp'] = file_timestamp
                credential['source_file'] = str(credential_file)
                credential['channel'] = channel_info['channel_name']
                credential['channel_username'] = channel_info['channel_username']
                credential['channel_id'] = channel_info['channel_id']
                credential['message_id'] = channel_info['message_id']
                credential['country_code'] = country_code
                credential['format'] = 'traditional'
                credentials.append(credential)
        
        return credentials
    
    def parse_all_credential_files(self, extract_dir: Path, extracted_files: List[str]) -> Dict[str, Any]:
        """
        Find and parse all credential files in the extracted archive.
        
        Args:
            extract_dir: Directory containing extracted files
            extracted_files: List of extracted file paths
            
        Returns:
            Dictionary with credential parsing results
        """
        result = {
            'credential_files_found': 0,
            'total_credentials': 0,
            'parsing_errors': [],
            'credential_files': [],
            'all_credentials': []
        }
        
        try:
            # Find credential files
            credential_files = self.find_credential_files(extract_dir, extracted_files)
            result['credential_files_found'] = len(credential_files)
            
            if not credential_files:
                self.logger.info("No credential files found in extracted archive")
                return result
            
            # Parse each credential file
            for credential_file in credential_files:
                try:
                    self.logger.info(f"Parsing credential file: {credential_file}")
                    credentials = self.parse_credentials_file(credential_file)
                    
                    file_result = {
                        'file_path': str(credential_file),
                        'credentials_count': len(credentials),
                        'parsing_successful': True
                    }
                    
                    result['credential_files'].append(file_result)
                    result['all_credentials'].extend(credentials)
                    result['total_credentials'] += len(credentials)
                    
                    self.logger.info(f"Parsed {len(credentials)} credentials from {credential_file}")
                    
                except Exception as e:
                    error_msg = f"Error parsing credential file {credential_file}: {str(e)}"
                    result['parsing_errors'].append(error_msg)
                    self.logger.error(error_msg)
                    
                    # Add failed file to results
                    file_result = {
                        'file_path': str(credential_file),
                        'credentials_count': 0,
                        'parsing_successful': False,
                        'error': str(e)
                    }
                    result['credential_files'].append(file_result)
            
            self.logger.info(f"Credential parsing completed: {result['total_credentials']} credentials from {result['credential_files_found']} files")
            
        except Exception as e:
            self.logger.error(f"Error in credential file parsing: {e}")
            result['parsing_errors'].append(f"General error: {str(e)}")
        
        return result
    
    def _parse_json_log(self, log_file: Path) -> List[Dict[str, str]]:
        """Parse JSON log file for credentials."""
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            # Basic credential extraction from JSON
            # This can be expanded based on actual log formats
            credentials = []
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        if 'username' in item or 'password' in item or 'url' in item:
                            credentials.append(item)
            elif isinstance(data, dict):
                # Handle single object case
                if 'username' in data or 'password' in data or 'url' in data:
                    credentials.append(data)
            
            return credentials
            
        except Exception as e:
            self.logger.debug(f"Error parsing JSON log {log_file}: {e}")
            return []
    
    def _parse_csv_log(self, log_file: Path) -> List[Dict[str, str]]:
        """Parse CSV log file for credentials."""
        try:
            credentials = []
            
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                # Try to detect delimiter
                sample = f.read(1024)
                f.seek(0)
                
                sniffer = csv.Sniffer()
                delimiter = sniffer.sniff(sample).delimiter
                
                reader = csv.DictReader(f, delimiter=delimiter)
                for row in reader:
                    # Look for credential-like fields
                    credential_fields = ['username', 'password', 'url', 'login', 'email', 'host']
                    if any(field in row for field in credential_fields):
                        credentials.append(dict(row))
            
            return credentials
            
        except Exception as e:
            self.logger.debug(f"Error parsing CSV log {log_file}: {e}")
            return []
    
    def _parse_colon_separated_credentials(self, content: str) -> List[Dict[str, str]]:
        """
        Parse credentials in format: url:username:password
        Handles various URL formats including those with protocols and ports.
        
        Args:
            content: File content to parse
            
        Returns:
            List of credential dictionaries
        """
        credentials = []
        
        try:
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Skip empty lines, comments, and header lines
                if not line or line.startswith('#') or line.startswith('//') or line.startswith('-'):
                    continue
                
                # Skip obvious header/banner lines  
                if any(keyword in line.lower() for keyword in ['join telegram', 'clouds', 'url:login:pass', 'logs']):
                    continue
                
                # Skip starlink banner lines but not actual credential lines
                if 'starlink' in line.lower() and ('telegram' in line.lower() or 'join' in line.lower() or line.startswith('|')):
                    continue
                
                # Count colons to determine if this might be a credential line
                colon_count = line.count(':')
                
                # We need at least 2 colons for url:username:password
                # But handle cases where URL has protocol (https://) or port (:8080)
                if colon_count < 2:
                    continue
                
                # Try to parse as colon-separated credential
                credential = self._parse_single_colon_credential(line, line_num)
                if credential:
                    credentials.append(credential)
            
            self.logger.debug(f"Parsed {len(credentials)} colon-separated credentials")
            return credentials
            
        except Exception as e:
            self.logger.debug(f"Error parsing colon-separated credentials: {e}")
            return []
    
    def _parse_single_colon_credential(self, line: str, line_num: int) -> Optional[Dict[str, str]]:
        """
        Parse a single line containing colon-separated credentials.
        Handles complex cases with URLs containing colons.
        
        Args:
            line: Single line to parse
            line_num: Line number for debugging
            
        Returns:
            Credential dictionary or None if parsing failed
        """
        try:
            # Handle different URL formats
            # Pattern 1: https://domain.com:port/path:username:password
            # Pattern 2: domain.com:username:password
            # Pattern 3: subdomain.domain.com:username:password
            
            # First, try to identify if line starts with a protocol
            if line.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
                # Handle URLs with protocols
                # Split by '://' first to separate protocol
                protocol_split = line.split('://', 1)
                if len(protocol_split) != 2:
                    return None
                
                protocol = protocol_split[0]
                remainder = protocol_split[1]
                
                # Now find the last two colons for username:password
                colon_positions = [i for i, char in enumerate(remainder) if char == ':']
                
                if len(colon_positions) < 2:
                    return None
                
                # Take the last two colons as separators
                username_colon = colon_positions[-2]
                password_colon = colon_positions[-1]
                
                url_part = remainder[:username_colon]
                username = remainder[username_colon + 1:password_colon]
                password = remainder[password_colon + 1:]
                
                # Reconstruct full URL
                full_url = f"{protocol}://{url_part}"
                
            else:
                # Handle simple domain:username:password format
                parts = line.split(':')
                
                if len(parts) < 3:
                    return None
                
                # For simple cases, assume last two parts are username:password
                # Everything before that is the URL/domain
                url_parts = parts[:-2]
                username = parts[-2]
                password = parts[-1]
                
                full_url = ':'.join(url_parts)
            
            # Validate components
            if not full_url or not username or not password:
                return None
            
            # Clean up components
            full_url = full_url.strip()
            username = username.strip()
            password = password.strip()
            
            # Additional validation
            if len(username) < 1 or len(password) < 1:
                return None
            
            # Skip obvious false positives
            if any(fp in username.lower() for fp in ['username', 'user', 'login', 'email']):
                return None
            
            if any(fp in password.lower() for fp in ['password', 'pass', 'pwd']):
                return None
            
            # Create credential dictionary
            credential = {
                'url': full_url,
                'username': username,
                'password': password,
                'software': 'web_browser',  # Default software type
                'line_number': line_num,
                'format': 'colon_separated',
                'raw_line': line
            }
            
            self.logger.debug(f"Parsed colon-separated credential: {full_url} | {username}")
            return credential
            
        except Exception as e:
            self.logger.debug(f"Error parsing line {line_num}: {e}")
            return None
    
    def _parse_text_log(self, log_file: Path) -> List[Dict[str, str]]:
        """Parse text log file for credentials."""
        try:
            credentials = []
            
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # First, try to parse colon-separated credentials (url:username:password)
            colon_separated_credentials = self._parse_colon_separated_credentials(content)
            if colon_separated_credentials:
                credentials.extend(colon_separated_credentials)
            
            # Then, try simple regex patterns for common credential formats
            patterns = [
                r'(?i)username[:\s]+([^\r\n]+)',
                r'(?i)password[:\s]+([^\r\n]+)',
                r'(?i)url[:\s]+([^\r\n]+)',
                r'(?i)email[:\s]+([^\r\n]+)',
                r'(?i)host[:\s]+([^\r\n]+)',
                r'(?i)login[:\s]+([^\r\n]+)',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if match.strip():
                        credentials.append({'value': match.strip(), 'type': 'extracted'})
            
            return credentials
            
        except Exception as e:
            self.logger.debug(f"Error parsing text log {log_file}: {e}")
            return []
    
    def get_parser_statistics(self) -> Dict[str, Any]:
        """
        Get parser statistics and configuration.
        
        Returns:
            Dictionary with parser status
        """
        return {
            'parser_name': 'boxed.pw',
            'max_file_size': self.max_file_size,
            'supported_extensions': list(self.log_extensions),
            'search_keywords': self.log_keywords
        }


def main():
    """
    Command-line interface for testing the boxed.pw log parser.
    """
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='Test boxed.pw log parser')
    parser.add_argument('extract_dir', help='Directory containing extracted files')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--max-size', type=int, help='Maximum file size to process (bytes)')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    
    # Create parser
    log_parser = BoxedPwLogParser(max_file_size=args.max_size)
    
    extract_dir = Path(args.extract_dir)
    
    if not extract_dir.exists():
        print(f"Error: Directory not found: {extract_dir}")
        sys.exit(1)
    
    # Get list of extracted files
    extracted_files = []
    for file_path in extract_dir.rglob('*'):
        if file_path.is_file():
            extracted_files.append(str(file_path.relative_to(extract_dir)))
    
    # Parse logs
    result = log_parser.parse_extracted_logs(extract_dir, extracted_files)
    
    # Print results
    print("\nLog Parsing Results:")
    print("=" * 50)
    print(f"Total Files: {result['total_files']}")
    print(f"Log Files Found: {result['log_files_processed']}")
    print(f"Credentials Found: {result['credentials_found']}")
    print(f"File Types: {result['file_types']}")
    
    if result['parsing_errors']:
        print(f"\nErrors: {len(result['parsing_errors'])}")
        for error in result['parsing_errors']:
            print(f"  - {error}")
    
    if result['parsed_files']:
        print(f"\nParsed Files Details:")
        for file_result in result['parsed_files']:
            print(f"  {file_result['file_path']}: {file_result['credentials_count']} credentials")


if __name__ == "__main__":
    main()