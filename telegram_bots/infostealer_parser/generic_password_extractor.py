#!/usr/bin/env python3
"""
Generic Password Extractor Module for EntroSpies project.
Extracts passwords from Telegram message text using configurable patterns from JSON file.
Can be used by any infostealer workflow.
"""

import re
import json
import logging
import os
from typing import Optional, List, Dict, Union
from pathlib import Path
from parsing_failure_logger import ParsingFailureLogger

class GenericPasswordExtractor:
    """
    Generic password extractor that loads patterns from a JSON configuration file.
    Can be used by any infostealer workflow with channel-specific optimizations.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None, 
                 patterns_file: Optional[str] = None, 
                 channel_name: Optional[str] = None,
                 failure_logger: Optional[ParsingFailureLogger] = None):
        """
        Initialize the password extractor with patterns from JSON file.
        
        Args:
            logger: Optional logger instance for debugging
            patterns_file: Path to JSON file containing password patterns
            channel_name: Name of the channel for pattern optimization (e.g., 'boxed.pw', 'redline')
            failure_logger: Optional failure logger for tracking parsing failures
        """
        self.logger = logger or logging.getLogger(__name__)
        self.channel_name = channel_name or 'generic'
        self.failure_logger = failure_logger
        
        # Default patterns file location
        if patterns_file is None:
            current_dir = Path(__file__).parent
            patterns_file = current_dir.parent / "config" / "password_patterns.json"
        
        self.patterns_file = Path(patterns_file)
        
        # Load patterns from JSON file
        self.password_patterns = []
        self.validation_rules = {}
        self.channel_config = {}
        
        self._load_patterns()
        
        self.logger.info(f"Generic password extractor initialized for channel: {self.channel_name}")
        self.logger.info(f"Loaded {len(self.password_patterns)} patterns from {self.patterns_file}")
    
    def _load_patterns(self):
        """Load password patterns from JSON configuration file."""
        try:
            with open(self.patterns_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Load patterns
            patterns = config.get('patterns', [])
            
            # Filter patterns for this channel and sort by priority
            channel_patterns = []
            for pattern in patterns:
                if self.channel_name in pattern.get('channels', []):
                    channel_patterns.append(pattern)
            
            # If no channel-specific patterns found, use all patterns
            if not channel_patterns:
                self.logger.warning(f"No patterns found for channel '{self.channel_name}', using all patterns")
                channel_patterns = patterns
            
            # Convert string flags to regex flags
            for pattern in channel_patterns:
                flags = 0
                for flag_name in pattern.get('flags', []):
                    if flag_name == 'IGNORECASE':
                        flags |= re.IGNORECASE
                    elif flag_name == 'MULTILINE':
                        flags |= re.MULTILINE
                    elif flag_name == 'DOTALL':
                        flags |= re.DOTALL
                pattern['compiled_flags'] = flags
            
            # Sort by priority (lower number = higher priority)
            channel_patterns.sort(key=lambda x: x.get('priority', 999))
            
            # Apply channel-specific priority boost
            channel_config = config.get('channel_specific_configs', {}).get(self.channel_name, {})
            preferred_patterns = channel_config.get('preferred_patterns', [])
            priority_boost = channel_config.get('priority_boost', 0)
            
            if preferred_patterns:
                # Boost priority of preferred patterns
                for pattern in channel_patterns:
                    if pattern['name'] in preferred_patterns:
                        pattern['priority'] = pattern.get('priority', 999) - priority_boost
                
                # Re-sort after priority boost
                channel_patterns.sort(key=lambda x: x.get('priority', 999))
            
            self.password_patterns = channel_patterns
            self.validation_rules = config.get('validation_rules', {})
            self.channel_config = channel_config
            
            self.logger.debug(f"Loaded {len(self.password_patterns)} patterns for channel '{self.channel_name}'")
            
        except FileNotFoundError:
            self.logger.error(f"Password patterns file not found: {self.patterns_file}")
            self._load_default_patterns()
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in patterns file: {e}")
            self._load_default_patterns()
        except Exception as e:
            self.logger.error(f"Error loading patterns file: {e}")
            self._load_default_patterns()
    
    def _load_default_patterns(self):
        """Load default hardcoded patterns as fallback."""
        self.logger.warning("Using default hardcoded patterns as fallback")
        
        self.password_patterns = [
            {
                'name': 'emoji_pass_code_block',
                'pattern': r'🔑\s*\.?pass:?\]\([^)]*\)\s*```([^`]+)```',
                'compiled_flags': re.IGNORECASE | re.MULTILINE,
                'priority': 1
            },
            {
                'name': 'password_label_code_block',
                'pattern': r'password\s*:?\s*```([^`]+)```',
                'compiled_flags': re.IGNORECASE | re.MULTILINE,
                'priority': 2
            },
            {
                'name': 'pass_label_simple',
                'pattern': r'pass\s*:?\s*([^\n\s]+)',
                'compiled_flags': re.IGNORECASE | re.MULTILINE,
                'priority': 3
            }
        ]
        
        self.validation_rules = {
            'min_length': 3,
            'max_length': 50,
            'false_positives': ['password', 'pass', '123456', 'admin', 'user', 'test']
        }
    
    def extract_password(self, message_text: str, message_file_path: Optional[str] = None,
                        channel_name: Optional[str] = None, message_id: Optional[int] = None) -> Optional[str]:
        """
        Extract password from message text using configured patterns.
        
        Args:
            message_text: The message text to analyze
            message_file_path: Path to the message file (for failure logging)
            channel_name: Channel name (for failure logging)
            message_id: Message ID (for failure logging)
            
        Returns:
            Extracted password string or None if no password found
        """
        if not message_text or not isinstance(message_text, str):
            return None
        
        self.logger.debug(f"Analyzing message text for passwords: {message_text[:100]}...")
        
        patterns_tried = []
        
        # Try each pattern in order of priority
        for pattern_info in self.password_patterns:
            pattern = pattern_info['pattern']
            flags = pattern_info['compiled_flags']
            name = pattern_info['name']
            patterns_tried.append(name)
            
            try:
                matches = re.findall(pattern, message_text, flags)
                if matches:
                    # Get the first match and clean it
                    password = self._clean_password(matches[0])
                    if self._is_valid_password(password):
                        self.logger.info(f"Password extracted using pattern '{name}': {password}")
                        return password
                    else:
                        self.logger.debug(f"Pattern '{name}' matched but password failed validation: {password}")
            except Exception as e:
                self.logger.error(f"Error applying pattern '{name}': {e}")
        
        self.logger.debug("No valid password found in message text")
        
        # Log parsing failure if failure logger is available
        if self.failure_logger and message_file_path:
            self.failure_logger.log_password_extraction_failure(
                message_file_path=message_file_path,
                message_text=message_text,
                channel_name=channel_name or self.channel_name,
                message_id=message_id,
                patterns_tried=patterns_tried
            )
        
        return None
    
    def extract_passwords_batch(self, message_texts: List[str]) -> List[Optional[str]]:
        """
        Extract passwords from multiple message texts.
        
        Args:
            message_texts: List of message texts to analyze
            
        Returns:
            List of extracted passwords (None for messages without passwords)
        """
        return [self.extract_password(text) for text in message_texts]
    
    def extract_from_json_file(self, json_file_path: Union[str, Path]) -> Optional[str]:
        """
        Extract password from a JSON message file.
        
        Args:
            json_file_path: Path to the JSON file containing message data
            
        Returns:
            Extracted password string or None if no password found
        """
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                message_data = json.load(f)
            
            # Extract text from various possible fields
            message_text = message_data.get('text', '')
            if not message_text:
                # Try alternative field names
                message_text = message_data.get('message', '') or message_data.get('content', '')
            
            if message_text:
                # Extract additional info for failure logging
                channel_name = message_data.get('channel', self.channel_name)
                message_id = message_data.get('message_id', 0)
                
                password = self.extract_password(
                    message_text=message_text,
                    message_file_path=str(json_file_path),
                    channel_name=channel_name,
                    message_id=message_id
                )
                if password:
                    self.logger.info(f"Password extracted from {json_file_path}: {password}")
                return password
            else:
                self.logger.warning(f"No text content found in {json_file_path}")
                # Log as a file access failure
                if self.failure_logger:
                    self.failure_logger.log_failure(
                        message_file_path=str(json_file_path),
                        failure_category='FILE_ACCESS',
                        failure_reason='No text content found in JSON file',
                        channel_name=message_data.get('channel', self.channel_name),
                        message_id=message_data.get('message_id', 0)
                    )
                return None
                
        except FileNotFoundError:
            self.logger.error(f"JSON file not found: {json_file_path}")
            if self.failure_logger:
                self.failure_logger.log_failure(
                    message_file_path=str(json_file_path),
                    failure_category='FILE_ACCESS',
                    failure_reason='JSON file not found',
                    error_details={'error': 'FileNotFoundError'}
                )
            return None
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in file {json_file_path}: {e}")
            if self.failure_logger:
                self.failure_logger.log_failure(
                    message_file_path=str(json_file_path),
                    failure_category='FORMAT_UNSUPPORTED',
                    failure_reason='Invalid JSON format',
                    error_details={'error': str(e)}
                )
            return None
        except Exception as e:
            self.logger.error(f"Error reading JSON file {json_file_path}: {e}")
            if self.failure_logger:
                self.failure_logger.log_failure(
                    message_file_path=str(json_file_path),
                    failure_category='FILE_ACCESS',
                    failure_reason='Error reading JSON file',
                    error_details={'error': str(e)}
                )
            return None
    
    def _clean_password(self, password: str) -> str:
        """
        Clean and normalize extracted password.
        
        Args:
            password: Raw extracted password string
            
        Returns:
            Cleaned password string
        """
        if not password:
            return ""
        
        # Remove common unwanted characters and whitespace
        cleaned = password.strip()
        
        # Remove markdown formatting
        cleaned = re.sub(r'[*_`~]', '', cleaned)
        
        # Remove URLs if accidentally captured (but preserve Telegram links as they can be passwords)
        if 't.me/' not in cleaned:
            cleaned = re.sub(r'https?://[^\s]+', '', cleaned)
        
        # Remove newlines and extra whitespace
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        
        return cleaned
    
    def _is_valid_password(self, password: str) -> bool:
        """
        Validate if extracted string is likely a real password using configured rules.
        
        Args:
            password: Password string to validate
            
        Returns:
            True if password appears valid, False otherwise
        """
        if not password:
            return False
        
        # Check length
        min_length = self.validation_rules.get('min_length', 3)
        max_length = self.validation_rules.get('max_length', 50)
        
        if len(password) < min_length or len(password) > max_length:
            return False
        
        # Check for false positives
        false_positives = set(self.validation_rules.get('false_positives', []))
        if password.lower() in false_positives:
            return False
        
        # Allow passwords that start with @ (common in Telegram)
        if self.validation_rules.get('allow_at_symbols', True):
            if password.startswith('@') and len(password) > 1:
                return True
        
        # Allow Telegram links as they are commonly used as passwords in infostealer channels
        if self.validation_rules.get('allow_telegram_links', True):
            if password.startswith(('http://', 'https://', 'www.')):
                if 't.me/' in password:
                    return True
                # Reject other URLs
                return False
        
        # Check if it contains only whitespace or special characters
        if not re.search(r'[A-Za-z0-9]', password):
            return False
        
        # Password seems valid
        return True
    
    def get_pattern_statistics(self, message_texts: List[str]) -> Dict[str, int]:
        """
        Get statistics about which patterns are most successful.
        
        Args:
            message_texts: List of message texts to analyze
            
        Returns:
            Dictionary with pattern names and success counts
        """
        stats = {pattern['name']: 0 for pattern in self.password_patterns}
        
        for text in message_texts:
            for pattern_info in self.password_patterns:
                pattern = pattern_info['pattern']
                flags = pattern_info['compiled_flags']
                name = pattern_info['name']
                
                try:
                    matches = re.findall(pattern, text, flags)
                    if matches:
                        password = self._clean_password(matches[0])
                        if self._is_valid_password(password):
                            stats[name] += 1
                            break  # Only count first successful pattern per message
                except Exception:
                    continue
        
        return stats
    
    def get_extractor_info(self) -> Dict:
        """
        Get information about the extractor configuration.
        
        Returns:
            Dictionary with extractor configuration details
        """
        return {
            'channel_name': self.channel_name,
            'patterns_file': str(self.patterns_file),
            'patterns_loaded': len(self.password_patterns),
            'validation_rules': self.validation_rules,
            'channel_config': self.channel_config,
            'pattern_names': [p['name'] for p in self.password_patterns]
        }
    
    def reload_patterns(self, new_channel_name: Optional[str] = None):
        """
        Reload patterns from file, optionally changing channel.
        
        Args:
            new_channel_name: New channel name to optimize for
        """
        if new_channel_name:
            self.channel_name = new_channel_name
            self.logger.info(f"Switching to channel: {self.channel_name}")
        
        self._load_patterns()
        self.logger.info(f"Reloaded {len(self.password_patterns)} patterns")
    
    @staticmethod
    def create_for_channel(channel_name: str, logger: Optional[logging.Logger] = None,
                          failure_logger: Optional[ParsingFailureLogger] = None) -> 'GenericPasswordExtractor':
        """
        Factory method to create a password extractor optimized for a specific channel.
        
        Args:
            channel_name: Name of the channel (e.g., 'boxed.pw', 'redline', 'raccoon')
            logger: Optional logger instance
            failure_logger: Optional failure logger for tracking parsing failures
            
        Returns:
            GenericPasswordExtractor instance optimized for the channel
        """
        return GenericPasswordExtractor(logger=logger, channel_name=channel_name, failure_logger=failure_logger)


def main():
    """
    Command-line interface for testing the generic password extractor.
    """
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='Extract passwords using generic password extractor')
    parser.add_argument('input', help='JSON file, directory path, or message text')
    parser.add_argument('-c', '--channel', default='generic', help='Channel name for pattern optimization')
    parser.add_argument('-p', '--patterns-file', help='Path to custom patterns JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-s', '--stats', action='store_true', help='Show pattern statistics')
    parser.add_argument('-i', '--info', action='store_true', help='Show extractor configuration info')
    parser.add_argument('-t', '--text', action='store_true', help='Treat input as message text instead of file/directory')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    
    # Create extractor
    extractor = GenericPasswordExtractor(
        channel_name=args.channel,
        patterns_file=args.patterns_file
    )
    
    if args.info:
        info = extractor.get_extractor_info()
        print("Extractor Configuration:")
        print("=" * 40)
        for key, value in info.items():
            print(f"{key}: {value}")
        print()
    
    if args.text:
        # Treat input as message text
        password = extractor.extract_password(args.input)
        if password:
            print(f"Password found: {password}")
        else:
            print("No password found")
            sys.exit(1)
    else:
        input_path = Path(args.input)
        
        if input_path.is_file():
            # Single file
            password = extractor.extract_from_json_file(input_path)
            if password:
                print(f"Password found: {password}")
            else:
                print("No password found")
                sys.exit(1)
        
        elif input_path.is_dir():
            # Directory processing
            results = {}
            json_files = list(input_path.glob("**/*message.json"))
            if not json_files:
                json_files = list(input_path.glob("**/*.json"))
            
            print(f"Processing {len(json_files)} JSON files...")
            passwords_found = 0
            
            for json_file in json_files:
                password = extractor.extract_from_json_file(json_file)
                results[str(json_file)] = password
                if password:
                    print(f"  {json_file}: {password}")
                    passwords_found += 1
                elif args.verbose:
                    print(f"  {json_file}: No password")
            
            print(f"\nSummary: {passwords_found}/{len(results)} files contained passwords")
            
            if args.stats and results:
                # Collect all message texts for statistics
                message_texts = []
                for file_path in results.keys():
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            if 'text' in data:
                                message_texts.append(data['text'])
                    except Exception:
                        continue
                
                if message_texts:
                    stats = extractor.get_pattern_statistics(message_texts)
                    print(f"\nPattern Statistics:")
                    for pattern_name, count in stats.items():
                        if count > 0:
                            print(f"  {pattern_name}: {count}")
        
        else:
            print(f"Error: {input_path} is neither a file nor a directory")
            sys.exit(1)


if __name__ == "__main__":
    main()