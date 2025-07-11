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
            
            self.logger.info(f"Found {len(log_files)} log files to parse")
            
        except Exception as e:
            self.logger.error(f"Error finding log files: {e}")
        
        return log_files
    
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
                    credentials.append(credential)
                    
        except Exception as e:
            self.logger.error(f"Error parsing credential file {credential_file}: {e}")
            
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
    
    def _parse_text_log(self, log_file: Path) -> List[Dict[str, str]]:
        """Parse text log file for credentials."""
        try:
            credentials = []
            
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Simple regex patterns for common credential formats
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