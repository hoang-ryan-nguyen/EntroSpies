#!/usr/bin/env python3
"""
Archive Decompressor Module for EntroSpies project.
Decompresses various archive formats (RAR, ZIP, TAR, TAR.GZ, etc.) using 7z binary.
"""

import os
import subprocess
import logging
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Union, Tuple
import shutil
import time

class ArchiveDecompressor:
    """
    Universal archive decompressor using 7z binary.
    Supports multiple archive formats including RAR, ZIP, TAR, TAR.GZ, 7Z, etc.
    """
    
    def __init__(self, sevenzip_path: str = None, logger: Optional[logging.Logger] = None):
        """
        Initialize the archive decompressor.
        
        Args:
            sevenzip_path: Path to 7z binary (defaults to bin/7zz)
            logger: Optional logger instance for debugging
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Default 7z binary path
        if sevenzip_path is None:
            current_dir = Path(__file__).parent
            sevenzip_path = current_dir / "bin" / "7zz"
        
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
        
        self.logger.info(f"Archive decompressor initialized with 7z at: {self.sevenzip_path}")
    
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
                self.logger.info("7z binary test successful")
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
            
            self.logger.info(f"Found {len(files)} files in archive: {archive_path}")
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
                       create_subfolder: bool = True) -> Tuple[bool, List[str]]:
        """
        Extract an archive to a specified directory.
        
        Args:
            archive_path: Path to the archive file
            extract_to: Directory to extract files to
            password: Optional password for encrypted archives
            overwrite: Whether to overwrite existing files
            create_subfolder: Whether to create a subfolder with archive name
            
        Returns:
            Tuple of (success: bool, extracted_files: List[str])
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
            return False, []
        
        # Build 7z command
        cmd = [str(self.sevenzip_path), 'x', str(archive_path), f'-o{final_extract_dir}']
        
        if password:
            cmd.extend(['-p' + password])
        
        if overwrite:
            cmd.append('-y')  # Yes to all prompts
        
        try:
            self.logger.info(f"Extracting {archive_path} to {final_extract_dir}")
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
                
                self.logger.info(f"Successfully extracted {len(extracted_files)} files in {extraction_time:.2f}s")
                return True, extracted_files
            else:
                self.logger.error(f"Extraction failed with return code {result.returncode}")
                self.logger.error(f"Error output: {result.stderr}")
                return False, []
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Extraction timeout for archive: {archive_path}")
            return False, []
        except Exception as e:
            self.logger.error(f"Error during extraction: {e}")
            return False, []
    
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
            self.logger.debug(f"Testing archive integrity: {archive_path}")
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
                                  max_attempts: int = 10) -> Tuple[bool, Optional[str], List[str]]:
        """
        Try to extract archive using a list of passwords.
        
        Args:
            archive_path: Path to the archive file
            extract_to: Directory to extract files to
            password_list: List of passwords to try
            max_attempts: Maximum number of password attempts
            
        Returns:
            Tuple of (success: bool, successful_password: Optional[str], extracted_files: List[str])
        """
        archive_path = Path(archive_path)
        
        if not archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {archive_path}")
        
        if not password_list:
            self.logger.warning("No passwords provided, trying without password")
            success, files = self.extract_archive(archive_path, extract_to, None)
            return success, None, files
        
        attempts = min(len(password_list), max_attempts)
        
        for i, password in enumerate(password_list[:attempts]):
            self.logger.info(f"Trying password {i+1}/{attempts}: {password[:3]}***")
            
            try:
                success, files = self.extract_archive(archive_path, extract_to, password)
                
                if success:
                    self.logger.info(f"Successfully extracted with password: {password}")
                    return True, password, files
                else:
                    self.logger.debug(f"Password failed: {password}")
                    
            except Exception as e:
                self.logger.debug(f"Error with password '{password}': {e}")
                continue
        
        self.logger.warning(f"Failed to extract archive with {attempts} password attempts")
        return False, None, []
    
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
        success, files = decompressor.extract_archive(
            archive_path, 
            args.output, 
            args.password,
            create_subfolder=not args.no_subfolder
        )
        
        if success:
            print(f"Successfully extracted {len(files)} files to: {args.output}")
        else:
            print("Extraction failed")
            sys.exit(1)


if __name__ == "__main__":
    main()