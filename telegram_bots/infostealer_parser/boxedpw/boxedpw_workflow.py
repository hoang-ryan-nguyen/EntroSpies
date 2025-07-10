#!/usr/bin/env python3
"""
Boxed.pw Channel Workflow Module for EntroSpies project.
Handles post-download processing for files from the .boxed.pw channel.
"""

import os
import json
import logging
import time
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Union, Any
import shutil
import tempfile

# Import required modules
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from boxedpw_password_extractor import PasswordExtractor
from archive_decompressor import ArchiveDecompressor


class BoxedPwWorkflow:
    """
    Workflow processor for .boxed.pw channel downloads.
    Handles password extraction, archive decompression, and log parsing.
    """
    
    def __init__(self, base_download_dir: str = None, logger: Optional[logging.Logger] = None):
        """
        Initialize the boxed.pw workflow processor.
        
        Args:
            base_download_dir: Base directory for downloads (defaults to ../download)
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Set base download directory
        if base_download_dir is None:
            current_dir = Path(__file__).parent
            base_download_dir = current_dir.parent.parent / "download"
        
        self.base_download_dir = Path(base_download_dir)
        
        # Initialize components
        self.password_extractor = PasswordExtractor(self.logger)
        self.archive_decompressor = ArchiveDecompressor(logger=self.logger)
        
        # Workflow configuration
        self.config = {
            'max_password_attempts': 10,
            'cleanup_failed_extractions': True,
            'preserve_original_archives': True,
            'extract_timeout': 300,  # 5 minutes
            'supported_archive_formats': {'.rar', '.zip', '.7z', '.tar', '.tar.gz'},
            'log_file_patterns': ['*.txt', '*.log', '*.csv', '*.json'],
            'max_extraction_size': 100 * 1024 * 1024,  # 100MB limit
        }
        
        self.logger.info("Boxed.pw workflow processor initialized")
    
    def process_download(self, channel_dir: Union[str, Path], 
                        date_folder: str, 
                        message_id: int,
                        message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a downloaded file from boxed.pw channel.
        
        Args:
            channel_dir: Channel directory path (.boxed.pw)
            date_folder: Date folder (YYYY-MM-DD)
            message_id: Telegram message ID
            message_data: Message metadata dictionary
            
        Returns:
            Dictionary with processing results
        """
        start_time = time.time()
        
        # Initialize result structure
        result = {
            'success': False,
            'message_id': message_id,
            'channel': '.boxed.pw',
            'date_folder': date_folder,
            'processing_time': 0,
            'password_extracted': None,
            'password_successful': None,
            'archive_extracted': False,
            'extracted_files': [],
            'log_files_found': [],
            'log_parsing_results': {},
            'errors': [],
            'warnings': []
        }
        
        try:
            # Build paths
            download_path = Path(channel_dir) / date_folder
            message_json_path = download_path / f"{message_id}_message.json"
            
            self.logger.info(f"Processing boxed.pw download - Message ID: {message_id}")
            
            # Step 1: Extract password from message
            password = self._extract_password_from_message(message_data, message_json_path)
            if password:
                result['password_extracted'] = password
                self.logger.info(f"Extracted password: {password}")
            else:
                result['warnings'].append("No password found in message")
                self.logger.warning(f"No password found for message {message_id}")
            
            # Step 2: Find downloaded archive file
            archive_file = self._find_archive_file(download_path, message_id)
            if not archive_file:
                result['errors'].append("No archive file found")
                self.logger.error(f"No archive file found for message {message_id}")
                return result
            
            self.logger.info(f"Found archive file: {archive_file}")
            
            # Step 3: Extract archive
            extraction_result = self._extract_archive(archive_file, password, result)
            
            # Step 4: Parse extracted logs if extraction successful
            if extraction_result['success']:
                log_parsing_result = self._parse_extracted_logs(
                    extraction_result['extract_dir'],
                    extraction_result['extracted_files']
                )
                result['log_parsing_results'] = log_parsing_result
            
            # Step 5: Cleanup if configured
            if extraction_result.get('extract_dir') and self.config['cleanup_failed_extractions']:
                if not extraction_result['success']:
                    self._cleanup_extraction_dir(extraction_result['extract_dir'])
            
            result['success'] = extraction_result['success']
            
        except Exception as e:
            self.logger.error(f"Error processing boxed.pw download: {e}")
            result['errors'].append(f"Processing error: {str(e)}")
        
        finally:
            result['processing_time'] = time.time() - start_time
            self.logger.info(f"Boxed.pw processing completed in {result['processing_time']:.2f}s")
        
        return result
    
    def _extract_password_from_message(self, message_data: Dict[str, Any], 
                                     message_json_path: Path) -> Optional[str]:
        """
        Extract password from message data or JSON file.
        
        Args:
            message_data: Message metadata dictionary
            message_json_path: Path to message JSON file
            
        Returns:
            Extracted password or None
        """
        try:
            # Try to extract from provided message data first
            message_text = message_data.get('text', '')
            if message_text:
                password = self.password_extractor.extract_password(message_text)
                if password:
                    return password
            
            # Fallback to reading from JSON file
            if message_json_path.exists():
                password = self.password_extractor.extract_from_json_file(message_json_path)
                if password:
                    return password
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error extracting password: {e}")
            return None
    
    def _find_archive_file(self, download_path: Path, message_id: int) -> Optional[Path]:
        """
        Find the downloaded archive file for a message.
        
        Args:
            download_path: Directory containing downloaded files
            message_id: Message ID to search for
            
        Returns:
            Path to archive file or None
        """
        try:
            if not download_path.exists():
                return None
            
            # Look for files with message ID in name
            for file_path in download_path.iterdir():
                if file_path.is_file():
                    # Check if filename contains message ID
                    if str(message_id) in file_path.name:
                        # Check if it's a supported archive format
                        if self.archive_decompressor.is_supported_format(file_path):
                            return file_path
            
            # Fallback: look for any archive file in the directory
            for file_path in download_path.iterdir():
                if file_path.is_file() and self.archive_decompressor.is_supported_format(file_path):
                    self.logger.warning(f"Found archive without message ID in name: {file_path}")
                    return file_path
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error finding archive file: {e}")
            return None
    
    def _extract_archive(self, archive_file: Path, password: Optional[str], 
                        result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract archive file using password.
        
        Args:
            archive_file: Path to archive file
            password: Extracted password
            result: Result dictionary to update
            
        Returns:
            Dictionary with extraction results
        """
        extraction_result = {
            'success': False,
            'extract_dir': None,
            'extracted_files': [],
            'successful_password': None
        }
        
        try:
            # Create extraction directory
            extract_dir = archive_file.parent / f"{archive_file.stem}_extracted"
            extraction_result['extract_dir'] = extract_dir
            
            self.logger.info(f"Extracting archive: {archive_file}")
            
            # Try extraction with extracted password first
            if password:
                success, files = self.archive_decompressor.extract_archive(
                    archive_file, 
                    extract_dir.parent,
                    password=password,
                    create_subfolder=True
                )
                
                if success:
                    extraction_result['success'] = True
                    extraction_result['extracted_files'] = files
                    extraction_result['successful_password'] = password
                    result['password_successful'] = password
                    result['archive_extracted'] = True
                    result['extracted_files'] = files
                    
                    self.logger.info(f"Successfully extracted {len(files)} files with password: {password}")
                    return extraction_result
                else:
                    result['warnings'].append(f"Extraction failed with extracted password: {password}")
                    self.logger.warning(f"Extraction failed with password: {password}")
            
            # Try extraction without password
            self.logger.info("Trying extraction without password")
            success, files = self.archive_decompressor.extract_archive(
                archive_file,
                extract_dir.parent,
                password=None,
                create_subfolder=True
            )
            
            if success:
                extraction_result['success'] = True
                extraction_result['extracted_files'] = files
                result['archive_extracted'] = True
                result['extracted_files'] = files
                
                self.logger.info(f"Successfully extracted {len(files)} files without password")
                return extraction_result
            
            # Try with common passwords if extracted password failed
            if password:
                common_passwords = [
                    password.lower(),
                    password.upper(),
                    password.replace('_', ''),
                    password.replace('-', ''),
                ]
                
                success, successful_password, files = self.archive_decompressor.extract_with_password_list(
                    archive_file,
                    extract_dir.parent,
                    common_passwords,
                    max_attempts=5
                )
                
                if success:
                    extraction_result['success'] = True
                    extraction_result['extracted_files'] = files
                    extraction_result['successful_password'] = successful_password
                    result['password_successful'] = successful_password
                    result['archive_extracted'] = True
                    result['extracted_files'] = files
                    
                    self.logger.info(f"Successfully extracted with modified password: {successful_password}")
                    return extraction_result
            
            result['errors'].append("Archive extraction failed with all attempted passwords")
            self.logger.error("Failed to extract archive with any password attempt")
            
        except Exception as e:
            self.logger.error(f"Error during archive extraction: {e}")
            result['errors'].append(f"Extraction error: {str(e)}")
        
        return extraction_result
    
    def _parse_extracted_logs(self, extract_dir: Path, extracted_files: List[str]) -> Dict[str, Any]:
        """
        Parse extracted log files for credentials and useful information.
        
        Args:
            extract_dir: Directory containing extracted files
            extracted_files: List of extracted file paths
            
        Returns:
            Dictionary with parsing results
        """
        parsing_result = {
            'log_files_processed': 0,
            'total_files': len(extracted_files),
            'credentials_found': 0,
            'parsing_errors': [],
            'file_types': {},
            'summary': {}
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
            log_files = self._find_log_files(extract_dir, extracted_files)
            parsing_result['log_files_processed'] = len(log_files)
            
            if log_files:
                self.logger.info(f"Found {len(log_files)} log files to parse")
                
                # Parse each log file
                for log_file in log_files:
                    try:
                        log_result = self._parse_single_log_file(log_file)
                        parsing_result['credentials_found'] += log_result.get('credentials_count', 0)
                    except Exception as e:
                        parsing_result['parsing_errors'].append(f"Error parsing {log_file}: {str(e)}")
                        self.logger.error(f"Error parsing log file {log_file}: {e}")
            
            # Generate summary
            parsing_result['summary'] = {
                'total_files': len(extracted_files),
                'log_files_found': len(log_files),
                'file_types': list(parsing_result['file_types'].keys()),
                'credentials_found': parsing_result['credentials_found'] > 0
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing extracted logs: {e}")
            parsing_result['parsing_errors'].append(f"General parsing error: {str(e)}")
        
        return parsing_result
    
    def _find_log_files(self, extract_dir: Path, extracted_files: List[str]) -> List[Path]:
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
            log_extensions = {'.txt', '.log', '.csv', '.json'}
            log_keywords = ['password', 'login', 'credential', 'browser', 'cookie', 'history'}
            
            for file_path in extracted_files:
                full_path = extract_dir / file_path
                
                if full_path.exists() and full_path.is_file():
                    file_name_lower = full_path.name.lower()
                    
                    # Check extension
                    if full_path.suffix.lower() in log_extensions:
                        log_files.append(full_path)
                        continue
                    
                    # Check filename for keywords
                    if any(keyword in file_name_lower for keyword in log_keywords):
                        log_files.append(full_path)
                        continue
            
        except Exception as e:
            self.logger.error(f"Error finding log files: {e}")
        
        return log_files
    
    def _parse_single_log_file(self, log_file: Path) -> Dict[str, Any]:
        """
        Parse a single log file for credentials.
        
        Args:
            log_file: Path to log file
            
        Returns:
            Dictionary with parsing results
        """
        result = {
            'file_path': str(log_file),
            'file_size': 0,
            'credentials_count': 0,
            'parsing_successful': False,
            'file_type': 'unknown'
        }
        
        try:
            if not log_file.exists():
                return result
            
            result['file_size'] = log_file.stat().st_size
            
            # Skip very large files
            if result['file_size'] > self.config['max_extraction_size']:
                self.logger.warning(f"Skipping large file: {log_file} ({result['file_size']} bytes)")
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
            
            result['credentials_count'] = len(credentials) if credentials else 0
            result['parsing_successful'] = True
            
            if result['credentials_count'] > 0:
                self.logger.info(f"Found {result['credentials_count']} credentials in {log_file}")
            
        except Exception as e:
            self.logger.error(f"Error parsing log file {log_file}: {e}")
        
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
            
            return credentials
            
        except Exception as e:
            self.logger.debug(f"Error parsing JSON log {log_file}: {e}")
            return []
    
    def _parse_csv_log(self, log_file: Path) -> List[Dict[str, str]]:
        """Parse CSV log file for credentials."""
        try:
            import csv
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
                    if any(field in row for field in ['username', 'password', 'url', 'login']):
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
    
    def _cleanup_extraction_dir(self, extract_dir: Path) -> None:
        """
        Clean up extraction directory.
        
        Args:
            extract_dir: Directory to clean up
        """
        try:
            if extract_dir.exists():
                shutil.rmtree(extract_dir)
                self.logger.info(f"Cleaned up extraction directory: {extract_dir}")
        except Exception as e:
            self.logger.error(f"Error cleaning up extraction directory: {e}")
    
    def get_workflow_status(self) -> Dict[str, Any]:
        """
        Get current workflow status and configuration.
        
        Returns:
            Dictionary with workflow status
        """
        return {
            'workflow_name': 'boxed.pw',
            'base_download_dir': str(self.base_download_dir),
            'password_extractor_ready': self.password_extractor is not None,
            'archive_decompressor_ready': self.archive_decompressor is not None,
            'config': self.config.copy()
        }


def main():
    """
    Command-line interface for testing the boxed.pw workflow.
    """
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='Test boxed.pw workflow processing')
    parser.add_argument('channel_dir', help='Channel directory path')
    parser.add_argument('date_folder', help='Date folder (YYYY-MM-DD)')
    parser.add_argument('message_id', type=int, help='Message ID')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    
    # Create workflow processor
    workflow = BoxedPwWorkflow()
    
    # Mock message data for testing
    message_data = {
        'text': '[= .pass:](https://t.me/c/1935880746/28) ```@LOGACTIVE```',
        'message_id': args.message_id
    }
    
    # Process download
    result = workflow.process_download(
        args.channel_dir,
        args.date_folder,
        args.message_id,
        message_data
    )
    
    # Print results
    print("\nWorkflow Processing Results:")
    print("=" * 50)
    print(f"Success: {result['success']}")
    print(f"Message ID: {result['message_id']}")
    print(f"Processing Time: {result['processing_time']:.2f}s")
    print(f"Password Extracted: {result['password_extracted']}")
    print(f"Password Successful: {result['password_successful']}")
    print(f"Archive Extracted: {result['archive_extracted']}")
    print(f"Extracted Files: {len(result['extracted_files'])}")
    
    if result['log_parsing_results']:
        print(f"Log Files Processed: {result['log_parsing_results']['log_files_processed']}")
        print(f"Credentials Found: {result['log_parsing_results']['credentials_found']}")
    
    if result['errors']:
        print(f"Errors: {result['errors']}")
    
    if result['warnings']:
        print(f"Warnings: {result['warnings']}")


if __name__ == "__main__":
    main()