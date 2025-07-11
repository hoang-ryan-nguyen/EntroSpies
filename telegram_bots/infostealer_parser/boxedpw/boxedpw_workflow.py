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
import sys

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

try:
    from boxedpw_password_extractor import PasswordExtractor
    from boxedpw_log_parser import BoxedPwLogParser
except ImportError:
    # Try relative import from same directory
    from .boxedpw_password_extractor import PasswordExtractor
    from .boxedpw_log_parser import BoxedPwLogParser

try:
    from archive_decompressor import ArchiveDecompressor
except ImportError:
    # Try importing from project root
    sys.path.insert(0, str(project_root))
    from archive_decompressor import ArchiveDecompressor

# Import Elasticsearch client
try:
    from elasticsearch.infostealer_elasticsearch_client import InfostealerElasticsearchClient
except ImportError:
    # Try importing from project root
    elasticsearch_path = project_root / "elasticsearch"
    sys.path.insert(0, str(elasticsearch_path))
    from infostealer_elasticsearch_client import InfostealerElasticsearchClient


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
        
        # Workflow configuration with environment variable support
        self.config = {
            'max_password_attempts': int(os.getenv('MAX_PASSWORD_ATTEMPTS', 10)),
            'cleanup_failed_extractions': os.getenv('CLEANUP_FAILED_EXTRACTIONS', 'True').lower() == 'true',
            'preserve_original_archives': os.getenv('PRESERVE_ORIGINAL_ARCHIVES', 'True').lower() == 'true',
            'extract_timeout': int(os.getenv('EXTRACTION_TIMEOUT', 300)),  # 5 minutes
            'supported_archive_formats': {'.rar', '.zip', '.7z', '.tar', '.tar.gz'},
            'log_file_patterns': ['*.txt', '*.log', '*.csv', '*.json'],
            'max_extraction_size': int(os.getenv('MAX_EXTRACTION_SIZE', 100 * 1024 * 1024)),  # 100MB limit
        }
        
        # Initialize components
        self.password_extractor = PasswordExtractor(self.logger)
        self.archive_decompressor = ArchiveDecompressor(logger=self.logger)
        self.log_parser = BoxedPwLogParser(logger=self.logger, max_file_size=self.config.get('max_extraction_size'))
        self.elasticsearch_client = InfostealerElasticsearchClient(
            logger=self.logger,
            parser_version='boxedpw-1.0'
        )
        
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
            'password_json_file': None,
            'password_saved_to_disk': False,
            'archive_extracted': False,
            'extracted_files': [],
            'log_files_found': [],
            'log_parsing_results': {},
            'errors': [],
            'warnings': []
        }
        
        try:
            # Build paths for new individual message folder structure
            download_path = Path(channel_dir) / date_folder / f"msg_{message_id}"
            message_json_path = download_path / "message.json"
            password_json_path = download_path / "password.json"
            
            self.logger.info(f"Processing boxed.pw download - Message ID: {message_id}")
            self.logger.debug(f"Message folder: {download_path}")
            self.logger.debug(f"Expected message JSON: {message_json_path}")
            self.logger.debug(f"Expected password JSON: {password_json_path}")
            
            # Step 1: Read password from saved password.json file
            password = self._read_password_from_json_file(password_json_path)
            if password:
                result['password_extracted'] = password
                self.logger.info(f"Read password from file for message {message_id}: {password}")
            else:
                result['warnings'].append("No password found in password.json")
                self.logger.warning(f"No password found in password.json for message {message_id}")
            
            # Step 2: Find downloaded archive file in message folder
            archive_file = self._find_archive_file(download_path, message_id)
            if not archive_file:
                result['errors'].append("No archive file found in message folder")
                self.logger.error(f"No archive file found in message folder for message {message_id}")
                return result
            
            # Step 2.1: Validate message-file pairing
            if not self._validate_message_file_pairing(message_id, archive_file, password):
                result['warnings'].append("Message-file pairing validation failed")
                self.logger.warning(f"Message-file pairing validation failed for message {message_id} and file {archive_file.name}")
            
            self.logger.info(f"Found archive file for message {message_id}: {archive_file.name}")
            
            # Step 2.2: Save password to JSON file immediately to prevent race conditions
            password_json_path = None
            if password:
                password_json_path = self._save_password_to_json(download_path, message_id, archive_file, password)
                if password_json_path:
                    result['password_json_file'] = str(password_json_path)
                    result['password_saved_to_disk'] = True
                    self.logger.info(f"Password saved to disk before decompression: {password_json_path}")
                else:
                    result['warnings'].append("Failed to save password to JSON file")
                    self.logger.warning("Failed to save password to JSON file, continuing with memory-only approach")
            
            # Step 3: Extract archive
            extraction_result = self._extract_archive(archive_file, password, result, password_json_path)
            
            # Step 4: Parse extracted logs if extraction successful
            if extraction_result['success']:
                log_parsing_result = self.log_parser.parse_extracted_logs(
                    extraction_result['extract_dir'],
                    extraction_result['extracted_files']
                )
                result['log_parsing_results'] = log_parsing_result
            
            # Step 5: Parse credential files if extraction successful
            if extraction_result['success']:
                credential_parsing_result = self.log_parser.parse_all_credential_files(
                    extraction_result['extract_dir'],
                    extraction_result['extracted_files']
                )
                result['credential_parsing_results'] = credential_parsing_result
                
                # Step 6: Upload credentials to Elasticsearch if enabled and credentials found
                if credential_parsing_result['total_credentials'] > 0 and self.elasticsearch_client.is_enabled():
                    self.logger.info(f"Uploading {credential_parsing_result['total_credentials']} credentials to Elasticsearch")
                    
                    # Initialize Elasticsearch connection
                    if self.elasticsearch_client.test_connection():
                        upload_result = self.elasticsearch_client.upload_credentials(
                            credential_parsing_result['all_credentials']
                        )
                        result['elasticsearch_upload'] = upload_result
                        
                        self.logger.info(f"Elasticsearch upload completed: {upload_result['uploaded']} uploaded, {upload_result['duplicates_skipped']} duplicates, {upload_result['errors']} errors")
                    else:
                        self.logger.error("Failed to connect to Elasticsearch")
                        result['elasticsearch_upload'] = {
                            'uploaded': 0,
                            'duplicates_skipped': 0,
                            'errors': 1,
                            'total_processed': 0,
                            'error_message': 'Failed to connect to Elasticsearch'
                        }
                elif credential_parsing_result['total_credentials'] > 0:
                    self.logger.info(f"Found {credential_parsing_result['total_credentials']} credentials but Elasticsearch upload is disabled")
                    result['elasticsearch_upload'] = {
                        'uploaded': 0,
                        'duplicates_skipped': 0,
                        'errors': 0,
                        'total_processed': 0,
                        'disabled': True
                    }
            
            # Step 7: Cleanup if configured
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
    
    def _read_password_from_json_file(self, password_json_path: Path) -> Optional[str]:
        """
        Read password from password.json file created by download manager.
        
        Args:
            password_json_path: Path to password.json file
            
        Returns:
            Extracted password or None
        """
        try:
            if not password_json_path.exists():
                self.logger.warning(f"Password JSON file not found: {password_json_path}")
                return None
            
            with open(password_json_path, 'r', encoding='utf-8') as f:
                password_data = json.load(f)
            
            password = password_data.get('extracted_password')
            if password:
                self.logger.info(f"Successfully read password from JSON file: {password}")
                return password
            else:
                self.logger.info("Password JSON file exists but no password found")
                return None
                
        except Exception as e:
            self.logger.error(f"Error reading password from JSON file: {e}")
            return None

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
        Find the downloaded archive file in the individual message folder.
        
        Args:
            download_path: Message folder containing downloaded files
            message_id: Message ID to search for
            
        Returns:
            Path to archive file or None
        """
        try:
            if not download_path.exists():
                self.logger.error(f"Message folder does not exist: {download_path}")
                return None
            
            # In individual message folder structure, we just need to find any archive file
            # excluding JSON files and extraction directories
            archive_files = []
            for file_path in download_path.iterdir():
                if file_path.is_file():
                    # Skip JSON files and check if it's a supported archive format
                    if not file_path.name.endswith('.json') and self.archive_decompressor.is_supported_format(file_path):
                        archive_files.append(file_path)
                        self.logger.debug(f"Found archive file: {file_path.name}")
            
            # Return the first archive file found
            if len(archive_files) == 1:
                self.logger.info(f"Found archive file for message {message_id}: {archive_files[0].name}")
                return archive_files[0]
            elif len(archive_files) > 1:
                self.logger.warning(f"Multiple archive files found for message {message_id}: {[f.name for f in archive_files]}")
                # Return the first one, but log the issue
                return archive_files[0]
            
            self.logger.error(f"No archive file found in message folder for message {message_id}")
            return None
            
        except Exception as e:
            self.logger.error(f"Error finding archive file for message {message_id}: {e}")
            return None
    
    def _validate_message_file_pairing(self, message_id: int, archive_file: Path, password: Optional[str]) -> bool:
        """
        Validate that the archive file belongs to the correct message.
        With individual message folders, pairing is guaranteed by folder structure.
        
        Args:
            message_id: Message ID
            archive_file: Archive file path
            password: Extracted password
            
        Returns:
            True if pairing is valid, False otherwise
        """
        try:
            # With individual message folder structure, the pairing is guaranteed
            # Just verify the file exists in the expected message folder
            expected_folder = f"msg_{message_id}"
            if expected_folder in str(archive_file.parent):
                self.logger.debug(f"Message-file pairing validation passed: {message_id} -> {archive_file.name}")
                return True
            
            # If the file is not in the expected folder, it's likely a mis-pairing
            self.logger.warning(f"File {archive_file.name} not in expected message folder msg_{message_id}")
            return False
            
        except Exception as e:
            self.logger.error(f"Error validating message-file pairing: {e}")
            return False
    
    def _extract_archive(self, archive_file: Path, password: Optional[str], 
                        result: Dict[str, Any], password_json_path: Optional[Path] = None) -> Dict[str, Any]:
        """
        Extract archive file using password.
        Reads password from JSON file first if available, falls back to memory password.
        
        Args:
            archive_file: Path to archive file
            password: Extracted password (fallback)
            result: Result dictionary to update
            password_json_path: Path to JSON file containing password
            
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
            
            # Try to read password from JSON file first (prevents race conditions)
            json_password = None
            if password_json_path:
                json_password = self._read_password_from_json(password_json_path)
            
            # Use JSON password if available, otherwise fall back to memory password
            active_password = json_password if json_password else password
            
            # Try extraction with extracted password first
            if active_password:
                success, files = self.archive_decompressor.extract_archive(
                    archive_file, 
                    extract_dir.parent,
                    password=active_password,
                    create_subfolder=True
                )
                
                if success:
                    extraction_result['success'] = True
                    extraction_result['extracted_files'] = files
                    extraction_result['successful_password'] = active_password
                    result['password_successful'] = active_password
                    result['archive_extracted'] = True
                    result['extracted_files'] = files
                    
                    source_info = "JSON file" if json_password else "memory"
                    self.logger.info(f"Successfully extracted {len(files)} files with password from {source_info}: {active_password}")
                    return extraction_result
                else:
                    result['warnings'].append(f"Extraction failed with extracted password: {active_password}")
                    self.logger.warning(f"Extraction failed with password: {active_password}")
            
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
            if active_password:
                common_passwords = [
                    active_password.lower(),
                    active_password.upper(),
                    active_password.replace('_', ''),
                    active_password.replace('-', ''),
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
    
    def _save_password_to_json(self, download_path: Path, message_id: int, 
                              archive_file: Path, password: str) -> Optional[Path]:
        """
        Save extracted password to JSON file immediately after extraction.
        This prevents race conditions and memory collisions during decompression.
        
        Args:
            download_path: Directory containing downloaded files
            message_id: Message ID for filename
            archive_file: Path to the archive file
            password: Extracted password
            
        Returns:
            Path to created JSON file or None if failed
        """
        try:
            # Validate inputs
            if not download_path or not download_path.exists():
                raise ValueError(f"Download path does not exist: {download_path}")
            
            if not password or not password.strip():
                raise ValueError("Password is empty or invalid")
            
            # Create password JSON file path
            password_json_path = download_path / f"{message_id}_password.json"
            
            # Prepare password data
            password_data = {
                "message_id": message_id,
                "channel": ".boxed.pw",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "downloaded_file": str(archive_file),
                "extracted_password": password,
                "password_source": "message_text",
                "extraction_successful": True
            }
            
            # Write to JSON file with proper encoding
            with open(password_json_path, 'w', encoding='utf-8') as f:
                json.dump(password_data, f, indent=2, ensure_ascii=False)
            
            # Verify the file was created and is readable
            if not password_json_path.exists():
                raise IOError(f"Password JSON file was not created: {password_json_path}")
            
            self.logger.info(f"Password saved to JSON file: {password_json_path}")
            return password_json_path
            
        except (ValueError, IOError, OSError) as e:
            self.logger.error(f"Failed to save password to JSON file: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error saving password to JSON file: {e}")
            return None

    def _read_password_from_json(self, password_json_path: Path) -> Optional[str]:
        """
        Safely read password from JSON file with comprehensive error handling.
        
        Args:
            password_json_path: Path to the JSON file containing password
            
        Returns:
            Password string or None if reading failed
        """
        try:
            # Validate file exists and is readable
            if not password_json_path or not password_json_path.exists():
                self.logger.warning(f"Password JSON file does not exist: {password_json_path}")
                return None
            
            if not password_json_path.is_file():
                self.logger.warning(f"Password JSON path is not a file: {password_json_path}")
                return None
            
            # Read and parse JSON file
            with open(password_json_path, 'r', encoding='utf-8') as f:
                password_data = json.load(f)
            
            # Extract password with validation
            if not isinstance(password_data, dict):
                self.logger.warning(f"Password JSON file contains invalid data structure: {password_json_path}")
                return None
            
            password = password_data.get('extracted_password')
            if not password or not isinstance(password, str):
                self.logger.warning(f"No valid password found in JSON file: {password_json_path}")
                return None
            
            self.logger.info(f"Successfully read password from JSON file: {password_json_path}")
            return password
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON format in password file {password_json_path}: {e}")
            return None
        except (IOError, OSError) as e:
            self.logger.error(f"Error reading password JSON file {password_json_path}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error reading password JSON file {password_json_path}: {e}")
            return None

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
            'log_parser_ready': self.log_parser is not None,
            'elasticsearch_client_ready': self.elasticsearch_client is not None,
            'elasticsearch_enabled': self.elasticsearch_client.is_enabled() if self.elasticsearch_client else False,
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