#!/usr/bin/env python3
"""
Archive Decompressor Module for EntroSpies project.
Decompresses various archive formats (RAR, ZIP, TAR, TAR.GZ, etc.) using 7z binary.
"""

import os
import subprocess
import logging
import tempfile
import platform
from pathlib import Path
from typing import Optional, List, Dict, Union, Tuple
import shutil
import time
from parsing_failure_logger import ParsingFailureLogger

class ArchiveDecompressor:
    """
    Universal archive decompressor using 7z binary.
    Supports multiple archive formats including RAR, ZIP, TAR, TAR.GZ, 7Z, etc.
    """
    
    def __init__(self, sevenzip_path: str = None, logger: Optional[logging.Logger] = None,
                 failure_logger: Optional[ParsingFailureLogger] = None):
        """
        Initialize the archive decompressor.
        
        Args:
            sevenzip_path: Path to 7z binary (defaults to bin/7zz)
            logger: Optional logger instance for debugging
            failure_logger: Optional failure logger for tracking parsing failures
        """
        self.logger = logger or logging.getLogger(__name__)
        self.failure_logger = failure_logger
        
        # Default 7z binary path - platform-aware
        if sevenzip_path is None:
            sevenzip_path = self._get_default_7z_path()
        
        self.sevenzip_path = Path(sevenzip_path)
        
        # Verify 7z binary exists
        if not self.sevenzip_path.exists():
            raise FileNotFoundError(f"7z binary not found at: {self.sevenzip_path}")
        
        # Make sure it's executable
        if not os.access(self.sevenzip_path, os.X_OK):
            try:
                os.chmod(self.sevenzip_path, 0o755)
            except PermissionError:
                self.logger.warning(f"Could not make 7z binary executable: {self.sevenzip_path}")
        
        # Supported archive formats
        self.supported_formats = {
            '.rar', '.zip', '.7z', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2',
            '.tar.xz', '.txz', '.tar.lz', '.tlz', '.tar.Z', '.tZ', '.gz', '.bz2',
            '.xz', '.lzma', '.Z', '.cab', '.iso', '.dmg', '.hfs', '.wim', '.swm',
            '.esd', '.fat', '.ntfs', '.exe', '.msi', '.deb', '.rpm', '.cpio',
            '.arj', '.lzh', '.lha', '.chm', '.nsis', '.udf', '.vhd', '.vhdx'
        }
        
        self.logger.debug(f"Archive decompressor initialized with 7z at: {self.sevenzip_path}")
    
    def _get_default_7z_path(self) -> Path:
        """
        Get the default 7z binary path based on the platform.
        
        Returns:
            Path to the appropriate 7z binary
        """
        system = platform.system().lower()
        
        if system == "darwin":  # macOS
            # Try Homebrew installation first
            homebrew_paths = [
                Path("/opt/homebrew/bin/7z"),  # Apple Silicon
                Path("/usr/local/bin/7z"),     # Intel Mac
            ]
            
            for path in homebrew_paths:
                if path.exists():
                    self.logger.debug(f"Found 7z binary via Homebrew: {path}")
                    return path
            
            # Try system paths
            system_paths = [
                Path("/usr/bin/7z"),
                Path("/usr/local/bin/7z"),
            ]
            
            for path in system_paths:
                if path.exists():
                    self.logger.debug(f"Found 7z binary in system path: {path}")
                    return path
            
            # If no system 7z found, suggest installation
            raise FileNotFoundError(
                "7z binary not found on macOS. Please install it using: brew install p7zip"
            )
        
        elif system == "linux":
            # Try system installation first
            system_paths = [
                Path("/usr/bin/7z"),
                Path("/usr/local/bin/7z"),
                Path("/usr/bin/7zz"),
                Path("/usr/local/bin/7zz"),
            ]
            
            for path in system_paths:
                if path.exists():
                    self.logger.debug(f"Found 7z binary in system path: {path}")
                    return path
            
            # Fallback to bundled Linux binary if available
            current_dir = Path(__file__).parent
            bundled_path = current_dir / "bin" / "7zz"
            
            if bundled_path.exists():
                self.logger.debug(f"Using bundled 7z binary: {bundled_path}")
                return bundled_path
            
            raise FileNotFoundError(
                "7z binary not found on Linux. Please install it using your package manager (e.g., apt install p7zip-full)"
            )
        
        elif system == "windows":
            # Windows paths
            windows_paths = [
                Path("C:/Program Files/7-Zip/7z.exe"),
                Path("C:/Program Files (x86)/7-Zip/7z.exe"),
            ]
            
            for path in windows_paths:
                if path.exists():
                    self.logger.debug(f"Found 7z binary on Windows: {path}")
                    return path
            
            raise FileNotFoundError(
                "7z binary not found on Windows. Please install 7-Zip from https://www.7-zip.org/"
            )
        
        else:
            raise OSError(f"Unsupported platform: {system}")
    
    def test_7z_binary(self) -> bool:
        """
        Test if 7z binary is working properly.
        
        Returns:
            True if 7z binary is working, False otherwise
        """
        try:
            result = subprocess.run(
                [str(self.sevenzip_path), '--help'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return True
            else:
                self.logger.error(f"7z binary test failed with return code: {result.returncode}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("7z binary test timed out")
            return False
        except Exception as e:
            self.logger.error(f"Error testing 7z binary: {e}")
            return False
    
    def is_supported_format(self, file_path: Union[str, Path]) -> bool:
        """
        Check if file format is supported for decompression.
        
        Args:
            file_path: Path to the archive file
            
        Returns:
            True if format is supported, False otherwise
        """
        file_path = Path(file_path)
        
        # Check for compound extensions first (e.g., .tar.gz)
        name_lower = file_path.name.lower()
        for ext in sorted(self.supported_formats, key=len, reverse=True):
            if name_lower.endswith(ext):
                return True
        
        return False
    
    def is_wrong_password_error(self, return_code: int, error_output: str) -> bool:
        """
        Detect if extraction failed due to wrong password.
        
        Args:
            return_code: 7z process return code
            error_output: Error output from 7z command
            
        Returns:
            True if error is due to wrong password, False otherwise
        """
        # 7z typically returns exit code 2 for wrong password
        if return_code != 2:
            return False
        
        # Check for common wrong password error message patterns
        error_patterns = [
            "Wrong password?",
            "Cannot open encrypted archive. Wrong password?",
            "CRC failed: Wrong password?",
            "ERROR: Wrong password",
            "Data error : Wrong password?",
            "Cannot open encrypted archive"
        ]
        
        error_lower = error_output.lower()
        for pattern in error_patterns:
            if pattern.lower() in error_lower:
                return True
        
        return False
    
    def cleanup_on_wrong_password(self, archive_path: Union[str, Path], 
                                 preserve_json: bool = True) -> bool:
        """
        Clean up archive file when wrong password is detected.
        Optionally preserve JSON metadata files.
        
        Args:
            archive_path: Path to the archive file to delete
            preserve_json: Whether to preserve JSON files (default: True)
            
        Returns:
            True if cleanup successful, False otherwise
        """
        archive_path = Path(archive_path)
        
        if not archive_path.exists():
            self.logger.warning(f"Archive file not found for cleanup: {archive_path}")
            return True
        
        try:
            # Delete the archive file
            archive_path.unlink()
            self.logger.info(f"Deleted archive with wrong password: {archive_path}")
            
            # If preserve_json is False, also delete related JSON files
            if not preserve_json:
                archive_dir = archive_path.parent
                archive_stem = archive_path.stem
                
                # Look for related JSON files (message.json, password.json, etc.)
                json_files = list(archive_dir.glob(f"*{archive_stem}*.json"))
                json_files.extend(list(archive_dir.glob("*message.json")))
                json_files.extend(list(archive_dir.glob("*password.json")))
                
                for json_file in json_files:
                    try:
                        json_file.unlink()
                        self.logger.info(f"Deleted related JSON file: {json_file}")
                    except Exception as e:
                        self.logger.warning(f"Failed to delete JSON file {json_file}: {e}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup archive with wrong password: {e}")
            return False
    
    def list_archive_contents(self, archive_path: Union[str, Path], password: Optional[str] = None) -> List[str]:
        """
        List contents of an archive without extracting.
        
        Args:
            archive_path: Path to the archive file
            password: Optional password for encrypted archives
            
        Returns:
            List of file paths in the archive
        """
        archive_path = Path(archive_path)
        
        if not archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {archive_path}")
        
        if not self.is_supported_format(archive_path):
            raise ValueError(f"Unsupported archive format: {archive_path}")
        
        # Build 7z command
        cmd = [str(self.sevenzip_path), 'l', str(archive_path)]
        
        if password:
            cmd.extend(['-p' + password])
        
        try:
            self.logger.debug(f"Listing contents of: {archive_path}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                self.logger.error(f"Failed to list archive contents: {result.stderr}")
                return []
            
            # Parse 7z output to extract file names
            files = []
            lines = result.stdout.split('\n')
            in_file_list = False
            
            for line in lines:
                line = line.strip()
                if line.startswith('----------'):
                    in_file_list = not in_file_list
                    continue
                
                if in_file_list and line:
                    # 7z list format: Date Time Attr Size Compressed Name
                    parts = line.split()
                    if len(parts) >= 6:
                        # File name is the last part, may contain spaces
                        filename = ' '.join(parts[5:])
                        if filename and not filename.endswith('/'):  # Skip directories
                            files.append(filename)
            
            return files
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout listing archive contents: {archive_path}")
            return []
        except Exception as e:
            self.logger.error(f"Error listing archive contents: {e}")
            return []
    
    def extract_archive(self, archive_path: Union[str, Path], 
                       extract_to: Union[str, Path], 
                       password: Optional[str] = None,
                       overwrite: bool = True,
                       create_subfolder: bool = True,
                       message_file_path: Optional[str] = None,
                       channel_name: Optional[str] = None,
                       message_id: Optional[int] = None,
                       cleanup_on_wrong_password: bool = False) -> Tuple[bool, List[str], bool]:
        """
        Extract an archive to a specified directory.
        
        Args:
            archive_path: Path to the archive file
            extract_to: Directory to extract files to
            password: Optional password for encrypted archives
            overwrite: Whether to overwrite existing files
            create_subfolder: Whether to create a subfolder with archive name
            message_file_path: Path to message file (for failure logging)
            channel_name: Channel name (for failure logging)
            message_id: Message ID (for failure logging)
            cleanup_on_wrong_password: Whether to cleanup archive on wrong password (default: False)
            
        Returns:
            Tuple of (success: bool, extracted_files: List[str], wrong_password: bool)
        """
        archive_path = Path(archive_path)
        extract_to = Path(extract_to)
        
        if not archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {archive_path}")
        
        if not self.is_supported_format(archive_path):
            raise ValueError(f"Unsupported archive format: {archive_path}")
        
        # Create extraction directory
        if create_subfolder:
            archive_name = archive_path.stem
            if archive_name.endswith('.tar'):  # Handle .tar.gz, .tar.bz2, etc.
                archive_name = Path(archive_name).stem
            final_extract_dir = extract_to / archive_name
        else:
            final_extract_dir = extract_to
        
        try:
            final_extract_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.logger.error(f"Failed to create extraction directory: {e}")
            return False, [], False
        
        # Build 7z command
        cmd = [str(self.sevenzip_path), 'x', str(archive_path), f'-o{final_extract_dir}']
        
        if password:
            cmd.extend(['-p' + password])
        
        if overwrite:
            cmd.append('-y')  # Yes to all prompts
        
        try:
            start_time = time.time()
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            extraction_time = time.time() - start_time
            
            if result.returncode == 0:
                # Get list of extracted files
                extracted_files = []
                if final_extract_dir.exists():
                    for root, dirs, files in os.walk(final_extract_dir):
                        for file in files:
                            rel_path = os.path.relpath(os.path.join(root, file), final_extract_dir)
                            extracted_files.append(rel_path)
                
                self.logger.info(f"Archive extracted: {len(extracted_files)} files in {extraction_time:.2f}s")
                return True, extracted_files, False
            else:
                self.logger.error(f"Extraction failed with return code {result.returncode}")
                self.logger.error(f"Error output: {result.stderr}")
                
                # Check if it's a wrong password error
                is_wrong_password = self.is_wrong_password_error(result.returncode, result.stderr)
                
                if is_wrong_password:
                    self.logger.warning(f"Detected wrong password error for archive: {archive_path}")
                    
                    # Cleanup archive if requested
                    if cleanup_on_wrong_password:
                        cleanup_success = self.cleanup_on_wrong_password(archive_path, preserve_json=True)
                        if cleanup_success:
                            self.logger.info(f"Cleaned up archive with wrong password: {archive_path}")
                        else:
                            self.logger.error(f"Failed to cleanup archive with wrong password: {archive_path}")
                
                # Log extraction failure
                if self.failure_logger and message_file_path:
                    failure_type = "wrong_password" if is_wrong_password else "extraction_failure"
                    self.failure_logger.log_archive_decompression_failure(
                        message_file_path=message_file_path,
                        archive_path=archive_path,
                        password_used=password,
                        error_message=result.stderr,
                        channel_name=channel_name,
                        message_id=message_id,
                        failure_type=failure_type
                    )
                
                return False, [], is_wrong_password
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Extraction timeout for archive: {archive_path}")
            
            # Log timeout failure
            if self.failure_logger and message_file_path:
                self.failure_logger.log_archive_decompression_failure(
                    message_file_path=message_file_path,
                    archive_path=archive_path,
                    password_used=password,
                    error_message="Extraction timeout",
                    channel_name=channel_name,
                    message_id=message_id,
                    failure_type="extraction_timeout"
                )
            
            return False, [], False
        except Exception as e:
            self.logger.error(f"Error during extraction: {e}")
            
            # Log general extraction failure
            if self.failure_logger and message_file_path:
                self.failure_logger.log_archive_decompression_failure(
                    message_file_path=message_file_path,
                    archive_path=archive_path,
                    password_used=password,
                    error_message=str(e),
                    channel_name=channel_name,
                    message_id=message_id,
                    failure_type="extraction_exception"
                )
            
            return False, [], False
    
    def test_archive(self, archive_path: Union[str, Path], password: Optional[str] = None) -> bool:
        """
        Test archive integrity without extracting.
        
        Args:
            archive_path: Path to the archive file
            password: Optional password for encrypted archives
            
        Returns:
            True if archive is valid, False otherwise
        """
        archive_path = Path(archive_path)
        
        if not archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {archive_path}")
        
        if not self.is_supported_format(archive_path):
            raise ValueError(f"Unsupported archive format: {archive_path}")
        
        # Build 7z command
        cmd = [str(self.sevenzip_path), 't', str(archive_path)]
        
        if password:
            cmd.extend(['-p' + password])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                self.logger.info(f"Archive integrity test passed: {archive_path}")
                return True
            else:
                self.logger.warning(f"Archive integrity test failed: {archive_path}")
                self.logger.debug(f"Error output: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Archive test timeout: {archive_path}")
            return False
        except Exception as e:
            self.logger.error(f"Error testing archive: {e}")
            return False
    
    def extract_with_password_list(self, archive_path: Union[str, Path], 
                                  extract_to: Union[str, Path],
                                  password_list: List[str],
                                  max_attempts: int = 10,
                                  message_file_path: Optional[str] = None,
                                  channel_name: Optional[str] = None,
                                  message_id: Optional[int] = None,
                                  cleanup_on_wrong_password: bool = False) -> Tuple[bool, Optional[str], List[str], bool]:
        """
        Try to extract archive using a list of passwords.
        
        Args:
            archive_path: Path to the archive file
            extract_to: Directory to extract files to
            password_list: List of passwords to try
            max_attempts: Maximum number of password attempts
            message_file_path: Path to message file (for failure logging)
            channel_name: Channel name (for failure logging)
            message_id: Message ID (for failure logging)
            cleanup_on_wrong_password: Whether to cleanup archive on wrong password (default: False)
            
        Returns:
            Tuple of (success: bool, successful_password: Optional[str], extracted_files: List[str], any_wrong_password: bool)
        """
        archive_path = Path(archive_path)
        
        if not archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {archive_path}")
        
        if not password_list:
            self.logger.warning("No passwords provided, trying without password")
            success, files, wrong_password = self.extract_archive(archive_path, extract_to, None, 
                                                message_file_path=message_file_path,
                                                channel_name=channel_name,
                                                message_id=message_id,
                                                cleanup_on_wrong_password=cleanup_on_wrong_password)
            return success, None, files, wrong_password
        
        attempts = min(len(password_list), max_attempts)
        any_wrong_password = False
        
        for i, password in enumerate(password_list[:attempts]):
            self.logger.info(f"Trying password {i+1}/{attempts}: {password[:3]}***")
            
            try:
                success, files, wrong_password = self.extract_archive(archive_path, extract_to, password,
                                                    message_file_path=message_file_path,
                                                    channel_name=channel_name,
                                                    message_id=message_id,
                                                    cleanup_on_wrong_password=cleanup_on_wrong_password)
                
                if wrong_password:
                    any_wrong_password = True
                
                if success:
                    self.logger.info(f"Successfully extracted with password: {password}")
                    return True, password, files, any_wrong_password
                else:
                    self.logger.debug(f"Password failed: {password}")
                    
            except Exception as e:
                self.logger.debug(f"Error with password '{password}': {e}")
                continue
        
        self.logger.warning(f"Failed to extract archive with {attempts} password attempts")
        
        # Log final failure after all password attempts
        if self.failure_logger and message_file_path:
            failure_type = "wrong_password" if any_wrong_password else "password_attempts_exhausted"
            self.failure_logger.log_archive_decompression_failure(
                message_file_path=message_file_path,
                archive_path=archive_path,
                password_used=f"Tried {attempts} passwords",
                error_message=f"All {attempts} password attempts failed",
                channel_name=channel_name,
                message_id=message_id,
                failure_type=failure_type
            )
        
        return False, None, [], any_wrong_password
    
    def get_archive_info(self, archive_path: Union[str, Path]) -> Dict[str, Union[str, int, bool]]:
        """
        Get detailed information about an archive.
        
        Args:
            archive_path: Path to the archive file
            
        Returns:
            Dictionary with archive information
        """
        archive_path = Path(archive_path)
        
        if not archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {archive_path}")
        
        info = {
            'path': str(archive_path),
            'name': archive_path.name,
            'size': archive_path.stat().st_size,
            'supported': self.is_supported_format(archive_path),
            'file_count': 0,
            'compressed_size': 0,
            'uncompressed_size': 0,
            'compression_ratio': 0.0,
            'encrypted': False,
            'format': 'unknown'
        }
        
        if not info['supported']:
            return info
        
        # Use 7z to get detailed info
        cmd = [str(self.sevenzip_path), 'l', '-slt', str(archive_path)]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                file_count = 0
                total_size = 0
                packed_size = 0
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('Type = '):
                        info['format'] = line.split('=', 1)[1].strip()
                    elif line.startswith('Method = '):
                        method = line.split('=', 1)[1].strip()
                        if 'AES' in method or 'ZipCrypto' in method:
                            info['encrypted'] = True
                    elif line.startswith('Size = '):
                        try:
                            size = int(line.split('=', 1)[1].strip())
                            total_size += size
                            file_count += 1
                        except ValueError:
                            pass
                    elif line.startswith('Packed Size = '):
                        try:
                            packed_size += int(line.split('=', 1)[1].strip())
                        except ValueError:
                            pass
                
                info['file_count'] = file_count
                info['uncompressed_size'] = total_size
                info['compressed_size'] = packed_size
                
                if total_size > 0:
                    info['compression_ratio'] = (1 - packed_size / total_size) * 100
                
        except Exception as e:
            self.logger.debug(f"Error getting archive info: {e}")
        
        return info
    
    def cleanup_extraction(self, extract_dir: Union[str, Path]) -> bool:
        """
        Clean up extraction directory.
        
        Args:
            extract_dir: Directory to clean up
            
        Returns:
            True if cleanup successful, False otherwise
        """
        extract_dir = Path(extract_dir)
        
        if not extract_dir.exists():
            return True
        
        try:
            shutil.rmtree(extract_dir)
            self.logger.info(f"Cleaned up extraction directory: {extract_dir}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to cleanup extraction directory: {e}")
            return False


def main():
    """
    Command-line interface for testing the archive decompressor.
    """
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='Extract archives using 7z')
    parser.add_argument('archive', help='Path to archive file')
    parser.add_argument('-o', '--output', default='.', help='Output directory (default: current directory)')
    parser.add_argument('-p', '--password', help='Password for encrypted archives')
    parser.add_argument('-l', '--list', action='store_true', help='List contents without extracting')
    parser.add_argument('-t', '--test', action='store_true', help='Test archive integrity')
    parser.add_argument('-i', '--info', action='store_true', help='Show archive information')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--no-subfolder', action='store_true', help='Extract directly to output directory')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    
    # Create decompressor
    try:
        decompressor = ArchiveDecompressor()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Test 7z binary
    if not decompressor.test_7z_binary():
        print("Error: 7z binary test failed")
        sys.exit(1)
    
    archive_path = Path(args.archive)
    
    if not archive_path.exists():
        print(f"Error: Archive not found: {archive_path}")
        sys.exit(1)
    
    if not decompressor.is_supported_format(archive_path):
        print(f"Error: Unsupported archive format: {archive_path}")
        sys.exit(1)
    
    if args.info:
        # Show archive information
        info = decompressor.get_archive_info(archive_path)
        print(f"Archive Information:")
        print(f"  Path: {info['path']}")
        print(f"  Format: {info['format']}")
        print(f"  Size: {info['size']} bytes")
        print(f"  Files: {info['file_count']}")
        print(f"  Compressed: {info['compressed_size']} bytes")
        print(f"  Uncompressed: {info['uncompressed_size']} bytes")
        print(f"  Compression: {info['compression_ratio']:.1f}%")
        print(f"  Encrypted: {info['encrypted']}")
    
    elif args.list:
        # List contents
        files = decompressor.list_archive_contents(archive_path, args.password)
        if files:
            print(f"Archive contents ({len(files)} files):")
            for file in files:
                print(f"  {file}")
        else:
            print("No files found or failed to list contents")
    
    elif args.test:
        # Test archive integrity
        if decompressor.test_archive(archive_path, args.password):
            print("Archive integrity test: PASSED")
        else:
            print("Archive integrity test: FAILED")
            sys.exit(1)
    
    else:
        # Extract archive
        success, files, wrong_password = decompressor.extract_archive(
            archive_path, 
            args.output, 
            args.password,
            create_subfolder=not args.no_subfolder
        )
        
        if success:
            print(f"Successfully extracted {len(files)} files to: {args.output}")
        else:
            if wrong_password:
                print("Extraction failed: Wrong password")
            else:
                print("Extraction failed")
            sys.exit(1)


if __name__ == "__main__":
    main()