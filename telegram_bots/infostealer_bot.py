#!/usr/bin/env python3
"""
EntroSpies Infostealer Bot - Main Implementation
Collects messages and attachments from Telegram infostealer channels for defensive security purposes.
"""

import argparse
import asyncio
import sys
import json
import os
import re
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from telethon import TelegramClient, events
from telethon.errors import SessionPasswordNeededError, ChannelPrivateError, FloodWaitError
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import custom modules
from logger import setup_logging
from telethon_download_manager import TelethonDownloadManager as DownloadManager, get_media_size, format_file_size
from master_workflow_orchestrator import MasterWorkflowOrchestrator

# Default configuration
DEFAULT_SESSION = os.getenv('SESSION_NAME', 'entrospies_session')
DEFAULT_CONFIG = os.getenv('CONFIG_FILE', 'config/channel_list.json')
DEFAULT_OUTPUT_DIR = os.getenv('DOWNLOAD_DIR', 'download')
DEFAULT_LOGS_DIR = os.getenv('LOGS_DIR', 'logs')
DEFAULT_SESSION_DIR = os.getenv('SESSION_DIR', 'session')
DEFAULT_MESSAGES = int(os.getenv('DEFAULT_MESSAGES', 1))
DEFAULT_MAX_FILE_SIZE = int(os.getenv('DEFAULT_MAX_FILE_SIZE', 1024 * 1024 * 1024))  # 1GB

def parse_size(size_str):
    """Parse size string (e.g., '500MB', '1GB') to bytes."""
    if not size_str:
        return 0
    
    size_str = size_str.upper().strip()
    
    # Extract number and unit
    match = re.match(r'^(\d+(?:\.\d+)?)\s*([KMGT]?B?)$', size_str)
    if not match:
        raise ValueError(f"Invalid size format: {size_str}. Use formats like '500MB', '1GB', etc.")
    
    number, unit = match.groups()
    number = float(number)
    
    # Convert to bytes
    multipliers = {
        'B': 1,
        'KB': 1024,
        'MB': 1024 ** 2,
        'GB': 1024 ** 3,
        'TB': 1024 ** 4,
        '': 1,  # Default to bytes if no unit
    }
    
    if unit not in multipliers:
        raise ValueError(f"Unknown size unit: {unit}")
    
    return int(number * multipliers[unit])

def load_api_credentials():
    """Load Telegram API credentials from environment variables or config file."""
    # Try environment variables first
    env_api_id = os.getenv('TELEGRAM_API_ID')
    env_api_hash = os.getenv('TELEGRAM_API_HASH')
    
    if env_api_id and env_api_hash:
        try:
            api_id = int(env_api_id)
            api_hash = env_api_hash
            print("Using API credentials from environment variables")
            return api_id, api_hash
        except ValueError:
            print("Error: TELEGRAM_API_ID must be a valid integer")
            sys.exit(1)
    
    # Fallback to config file
    api_config_path = 'api_config.json'
    try:
        with open(api_config_path, 'r', encoding='utf-8') as f:
            api_config = json.load(f)
        
        telegram_api = api_config.get('telegram_api', {})
        api_id = telegram_api.get('api_id')
        api_hash = telegram_api.get('api_hash')
        
        # Handle template placeholders
        if isinstance(api_id, str) and api_id.startswith('${'):
            print(f"Warning: API config file appears to be a template. Please set actual values or use environment variables.")
            print("Environment variables: TELEGRAM_API_ID and TELEGRAM_API_HASH")
            sys.exit(1)
        
        if not api_id or not api_hash:
            raise ValueError("Missing api_id or api_hash in API configuration")
        
        return api_id, api_hash
        
    except FileNotFoundError:
        print(f"Error: API config file {api_config_path} not found")
        print("Please either:")
        print("1. Set environment variables: TELEGRAM_API_ID and TELEGRAM_API_HASH")
        print("2. Create an api_config.json file with your Telegram API credentials:")
        print('   {"telegram_api": {"api_id": YOUR_API_ID, "api_hash": "YOUR_API_HASH"}}')
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in API config file: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

def setup_argument_parser():
    """Setup comprehensive command-line argument parser."""
    parser = argparse.ArgumentParser(
        description='EntroSpies Infostealer Bot - Telegram message and attachment collector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                                    # Listen for new messages in real-time
  %(prog)s -m 10                             # Download 10 latest messages from each channel
  %(prog)s -s my_session -v                  # Custom session with verbose logging
  %(prog)s -m 10 --prevent-big-files         # Download 10 messages, skip large files
  %(prog)s -c config/custom_channels.json --max-file-size 500MB  # Custom config with 500MB limit
  %(prog)s --dry-run -vvv                    # Preview mode with maximum verbosity
  %(prog)s --channels "channel1,channel2"    # Process specific channels only
  %(prog)s -s session/qualgolab_telegram.session -c config/channel_list.json -vvv    # My favorite run command
        '''
    )
    
    # Session configuration
    parser.add_argument(
        '-s', '--session',
        default=DEFAULT_SESSION,
        help=f'Telegram session file path (default: {DEFAULT_SESSION})'
    )
    
    # Message count
    parser.add_argument(
        '-m', '--messages',
        type=int,
        default=None,
        help=f'Number of messages to download per channel (default: listen for new messages in real-time)'
    )
    
    # Logging verbosity
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='Increase logging verbosity (-v: INFO, -vv: DEBUG, -vvv: ALL)'
    )
    
    # Configuration file
    parser.add_argument(
        '-c', '--config',
        default=DEFAULT_CONFIG,
        help=f'Path to channel list file (default: {DEFAULT_CONFIG})'
    )
    
    
    # File size controls (mutually exclusive)
    size_group = parser.add_mutually_exclusive_group()
    size_group.add_argument(
        '--prevent-big-files',
        action='store_true',
        help='Prevent downloading files larger than 1GB'
    )
    size_group.add_argument(
        '--max-file-size',
        type=str,
        help='Maximum file size to download (e.g., 500MB, 2GB)'
    )
    
    # Output directory
    parser.add_argument(
        '-o', '--output',
        default=DEFAULT_OUTPUT_DIR,
        help=f'Download directory (default: {DEFAULT_OUTPUT_DIR})'
    )
    
    # Logs directory
    parser.add_argument(
        '--logs-dir',
        default=DEFAULT_LOGS_DIR,
        help=f'Logs directory (default: {DEFAULT_LOGS_DIR})'
    )
    
    # Dry run mode
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be processed without downloading'
    )
    
    # Channel filtering
    parser.add_argument(
        '--channels',
        type=str,
        help='Comma-separated list of specific channels to process'
    )
    
    parser.add_argument(
        '--exclude',
        type=str,
        help='Comma-separated list of channels to exclude'
    )
    
    # Output file
    parser.add_argument(
        '--output-file',
        default='infostealer_results.json',
        help='JSON output file for results (default: infostealer_results.json)'
    )
    
    return parser

def check_session_files(session_path):
    """Check for multiple session files and quit if more than one exists."""
    # If session path is provided and exists, use it
    if session_path != DEFAULT_SESSION and os.path.exists(session_path):
        return session_path
    
    # If no specific session provided, check the default session directory
    session_dir = DEFAULT_SESSION_DIR
    if not os.path.exists(session_dir):
        print(f"Error: Session directory does not exist: {session_dir}")
        sys.exit(1)
    
    # Find all .session files in the session directory
    session_files = [f for f in os.listdir(session_dir) if f.endswith('.session')]
    
    if len(session_files) == 0:
        print(f"Error: No .session files found in {session_dir} directory")
        print("Please create a session file first using the Telegram API")
        sys.exit(1)
    elif len(session_files) == 1:
        # Only one session file, use it
        selected_session = os.path.join(session_dir, session_files[0])
        print(f"Using session file: {selected_session}")
        return selected_session
    else:
        # Multiple session files found, quit with error message
        print(f"Error: Multiple session files found in {session_dir} directory:")
        for session_file in session_files:
            print(f"  - {session_file}")
        print("Only one .session file is allowed in the session directory.")
        print("Please specify which session file to use with the -s/--session option.")
        sys.exit(1)

def validate_arguments(args):
    """Validate and process command-line arguments."""
    # Handle session file selection
    args.session = check_session_files(args.session)
    
    # Validate session file directory
    session_dir = os.path.dirname(os.path.abspath(args.session)) if os.path.dirname(args.session) else '.'
    if not os.path.exists(session_dir):
        print(f"Error: Session directory does not exist: {session_dir}")
        sys.exit(1)
    
    # Validate config file
    if not os.path.exists(args.config):
        print(f"Error: Channel list file not found: {args.config}")
        sys.exit(1)
    
    
    # Parse and validate file size limits
    if args.prevent_big_files:
        args.max_file_size_bytes = DEFAULT_MAX_FILE_SIZE
    elif args.max_file_size:
        try:
            args.max_file_size_bytes = parse_size(args.max_file_size)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        args.max_file_size_bytes = None  # No limit
    
    # Validate message count (None means listening mode)
    if args.messages is not None and args.messages < 1:
        print("Error: Number of messages must be at least 1")
        sys.exit(1)
    
    # Set listening mode flag
    args.listening_mode = args.messages is None
    if args.listening_mode:
        args.messages = DEFAULT_MESSAGES  # Fallback for compatibility
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Create logs directory
    os.makedirs(args.logs_dir, exist_ok=True)
    
    # Process channel lists
    if args.channels:
        args.channels_list = [ch.strip() for ch in args.channels.split(',') if ch.strip()]
    else:
        args.channels_list = None
    
    if args.exclude:
        args.exclude_list = [ch.strip() for ch in args.exclude.split(',') if ch.strip()]
    else:
        args.exclude_list = None
    
    return args

def setup_dynamic_logging(args):
    """Setup logging with dynamic verbosity levels."""
    # Setup base logging
    logger, compliance_logger, error_logger = setup_logging(args.logs_dir)
    
    # Adjust logging levels based on verbosity
    console_level = logging.WARNING  # Default
    if args.verbose == 1:
        console_level = logging.INFO
    elif args.verbose == 2:
        console_level = logging.DEBUG
    elif args.verbose >= 3:
        console_level = logging.NOTSET  # Show everything
    
    # Update console handler levels
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler) and not hasattr(handler, 'baseFilename'):
            handler.setLevel(console_level)
    
    return logger, compliance_logger, error_logger

def sanitize_filename(filename):
    """Sanitize filename for safe directory creation."""
    # Remove/replace problematic characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = re.sub(r'[\s\[\]{}()]+', '_', filename)
    filename = filename.strip('._')
    return filename[:50]  # Limit length

def is_message_already_downloaded(channel_info, message_id, download_dir):
    """Check if message is already downloaded by looking for existing JSON file and attachments."""
    try:
        channel_dir = sanitize_filename(channel_info['title'])
        # Check multiple possible date folders (current and recent days)
        base_path = Path(download_dir) / channel_dir
        
        if not base_path.exists():
            return False
        
        # Look for message JSON file in any date folder
        for date_folder in base_path.iterdir():
            if date_folder.is_dir():
                message_file = date_folder / f"{message_id}_message.json"
                if message_file.exists():
                    # Message JSON exists, now check if attachments are also downloaded
                    # Look for any non-JSON files that might be attachments for this message
                    attachment_files = []
                    for file in date_folder.iterdir():
                        if file.is_file() and str(message_id) in file.name and not file.name.endswith('.json'):
                            attachment_files.append(file)
                    
                    # If we found attachment files, consider it fully downloaded
                    if attachment_files:
                        return True
                    
                    # If no attachments found, check the JSON file to see if message had media
                    try:
                        with open(message_file, 'r', encoding='utf-8') as f:
                            message_data = json.load(f)
                        
                        # If message had no media, then JSON file is sufficient
                        if not message_data.get('has_media', False):
                            return True
                        
                        # If message had media but no attachment files found, consider it incomplete
                        # Return False to allow re-download
                        return False
                        
                    except Exception:
                        # If can't read JSON, be safe and allow re-download
                        return False
        
        return False
    except Exception:
        return False

def get_download_status(channel_info, message_id, download_dir):
    """Get detailed download status for a message."""
    try:
        channel_dir = sanitize_filename(channel_info['title'])
        base_path = Path(download_dir) / channel_dir
        
        if not base_path.exists():
            return "No channel directory"
        
        # Look for message JSON file in any date folder
        for date_folder in base_path.iterdir():
            if date_folder.is_dir():
                message_file = date_folder / f"{message_id}_message.json"
                if message_file.exists():
                    # Count attachment files
                    attachment_files = []
                    for file in date_folder.iterdir():
                        if file.is_file() and str(message_id) in file.name and not file.name.endswith('.json'):
                            attachment_files.append(file.name)
                    
                    try:
                        with open(message_file, 'r', encoding='utf-8') as f:
                            message_data = json.load(f)
                        
                        has_media = message_data.get('has_media', False)
                        
                        if has_media and attachment_files:
                            return f"Complete (JSON + {len(attachment_files)} attachments: {', '.join(attachment_files)})"
                        elif has_media and not attachment_files:
                            return "Incomplete (JSON only, missing attachments)"
                        elif not has_media:
                            return "Complete (text-only message)"
                        
                    except Exception:
                        return "JSON file corrupted"
        
        return "Not found"
    except Exception:
        return "Error checking status"


def normalize_message_text(text):
    """
    Normalize message text for content comparison.
    Removes timestamps, usernames, and formatting inconsistencies.
    """
    if not text:
        return ""
    
    # Remove common variable elements
    normalized = text.lower().strip()
    
    # Remove timestamps (various formats)
    normalized = re.sub(r'\d{4}[-/]\d{2}[-/]\d{2}', '', normalized)
    normalized = re.sub(r'\d{2}[-/]\d{2}[-/]\d{4}', '', normalized)
    normalized = re.sub(r'\d{2}:\d{2}:\d{2}', '', normalized)
    normalized = re.sub(r'\d{2}:\d{2}', '', normalized)
    
    # Remove usernames/mentions
    normalized = re.sub(r'@\w+', '', normalized)
    
    # Remove URLs
    normalized = re.sub(r'https?://\S+', '', normalized)
    normalized = re.sub(r'www\.\S+', '', normalized)
    
    # Remove excessive whitespace
    normalized = re.sub(r'\s+', ' ', normalized)
    
    # Remove common formatting characters
    normalized = re.sub(r'[*_`~\[\](){}]', '', normalized)
    
    return normalized.strip()


def generate_content_hash(message_text, media_type=None, media_size=None):
    """
    Generate a hash of the message content for duplicate detection.
    
    Args:
        message_text: The message text content
        media_type: Type of media (if any)
        media_size: Size of media (if any)
        
    Returns:
        SHA-256 hash of the normalized content
    """
    # Normalize the text content
    normalized_text = normalize_message_text(message_text)
    
    # Create content string including media info
    content_parts = [normalized_text]
    
    if media_type:
        content_parts.append(f"media_type:{media_type}")
    
    if media_size:
        # Round media size to nearest KB to handle small variations
        size_kb = round(media_size / 1024)
        content_parts.append(f"media_size_kb:{size_kb}")
    
    content_string = "|".join(content_parts)
    
    # Generate SHA-256 hash
    return hashlib.sha256(content_string.encode('utf-8')).hexdigest()


def find_content_duplicate(message_text, media_type, media_size, channel_info, download_dir):
    """
    Find if a message with similar content already exists.
    
    Args:
        message_text: The message text to check
        media_type: Type of media (if any)
        media_size: Size of media (if any)
        channel_info: Channel information
        download_dir: Download directory path
        
    Returns:
        Tuple of (is_duplicate: bool, existing_message_id: int, similarity_reason: str)
    """
    try:
        # Generate hash for the new message
        new_hash = generate_content_hash(message_text, media_type, media_size)
        
        channel_dir = sanitize_filename(channel_info['title'])
        base_path = Path(download_dir) / channel_dir
        
        if not base_path.exists():
            return False, None, None
        
        # Search through all existing message files
        for date_folder in base_path.iterdir():
            if not date_folder.is_dir():
                continue
                
            for message_file in date_folder.glob("*_message.json"):
                try:
                    with open(message_file, 'r', encoding='utf-8') as f:
                        existing_data = json.load(f)
                    
                    # Skip if it's the same message ID (already handled by ID-based detection)
                    if str(existing_data.get('message_id')) in message_file.name:
                        continue
                    
                    # Generate hash for existing message
                    existing_text = existing_data.get('text', '')
                    existing_media_type = existing_data.get('media_type')
                    existing_media_size = existing_data.get('media_size')
                    
                    existing_hash = generate_content_hash(existing_text, existing_media_type, existing_media_size)
                    
                    # Check for exact content match
                    if new_hash == existing_hash:
                        existing_msg_id = existing_data.get('message_id')
                        return True, existing_msg_id, f"Exact content match (hash: {new_hash[:12]}...)"
                    
                    # Check for text similarity (if both have meaningful text)
                    if message_text and existing_text:
                        normalized_new = normalize_message_text(message_text)
                        normalized_existing = normalize_message_text(existing_text)
                        
                        # Check if normalized texts are identical
                        if normalized_new and normalized_existing and normalized_new == normalized_existing:
                            # Also check media similarity
                            media_similar = False
                            if not media_type and not existing_media_type:
                                media_similar = True  # Both text-only
                            elif media_type and existing_media_type:
                                # Same media type and similar size (within 5%)
                                if (media_type == existing_media_type and 
                                    media_size and existing_media_size and
                                    abs(media_size - existing_media_size) / max(media_size, existing_media_size) <= 0.05):
                                    media_similar = True
                            
                            if media_similar:
                                existing_msg_id = existing_data.get('message_id')
                                return True, existing_msg_id, f"Identical normalized text + similar media"
                    
                except Exception as e:
                    # Skip files that can't be read
                    continue
        
        return False, None, None
        
    except Exception as e:
        # If content duplicate detection fails, fall back to no duplicate
        return False, None, None


def is_message_already_downloaded_enhanced(channel_info, message_id, message_text, media_type, media_size, download_dir):
    """
    Enhanced duplicate detection that checks both message ID and content.
    
    Args:
        channel_info: Channel information
        message_id: Message ID to check
        message_text: Message text content
        media_type: Type of media (if any)
        media_size: Size of media (if any)
        download_dir: Download directory path
        
    Returns:
        Tuple of (is_duplicate: bool, duplicate_reason: str)
    """
    # First check ID-based duplicate (existing logic)
    if is_message_already_downloaded(channel_info, message_id, download_dir):
        return True, f"Message ID {message_id} already downloaded"
    
    # Then check content-based duplicate
    is_content_dup, existing_msg_id, similarity_reason = find_content_duplicate(
        message_text, media_type, media_size, channel_info, download_dir
    )
    
    if is_content_dup:
        return True, f"Content duplicate of message {existing_msg_id}: {similarity_reason}"
    
    return False, None

def load_channels_config(config_path, logger, compliance_logger, args):
    """Load channels from channel list file and filter based on arguments."""
    try:
        logger.info(f"Loading channels configuration from {config_path}")
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        channels = config.get('channels', [])
        logger.debug(f"Raw channels loaded: {len(channels)}")
        
        # Filter channels with specific parsers (not default) and validate priorities
        filtered_channels = []
        valid_priorities = {'high', 'medium', 'low'}
        
        for channel in channels:
            parser = channel.get('parser', '')
            if parser != 'infostealer_parser/_default.py':
                # Validate and set priority
                default_priority = os.getenv('DEFAULT_CHANNEL_PRIORITY', 'medium')
                priority = channel.get('priority', default_priority)
                if priority not in valid_priorities:
                    logger.warning(f"Invalid priority '{priority}' for channel {channel['title']}, defaulting to '{default_priority}'")
                    channel['priority'] = default_priority
                else:
                    channel['priority'] = priority
                
                filtered_channels.append(channel)
                compliance_logger.info(f"Channel selected for processing: {channel['title']} (ID: {channel['id']}, Parser: {parser}, Priority: {channel['priority']})")
        
        # Apply command-line channel filters
        if args.channels_list:
            # Filter to only specified channels
            final_channels = []
            for channel in filtered_channels:
                if (channel['title'] in args.channels_list or 
                    channel.get('username') in args.channels_list or
                    str(channel['id']) in args.channels_list):
                    final_channels.append(channel)
            filtered_channels = final_channels
            logger.info(f"Filtered to specified channels: {len(filtered_channels)}")
        
        if args.exclude_list:
            # Exclude specified channels
            final_channels = []
            for channel in filtered_channels:
                if not (channel['title'] in args.exclude_list or 
                       channel.get('username') in args.exclude_list or
                       str(channel['id']) in args.exclude_list):
                    final_channels.append(channel)
            excluded_count = len(filtered_channels) - len(final_channels)
            filtered_channels = final_channels
            logger.info(f"Excluded {excluded_count} channels")
        
        logger.info(f"Loaded {len(channels)} total channels")
        logger.info(f"Found {len(filtered_channels)} channels with specific parsers after filtering")
        compliance_logger.info(f"Channel filtering completed: {len(filtered_channels)} channels selected from {len(channels)} total")
        
        return filtered_channels
        
    except FileNotFoundError:
        logger.error(f"Config file {config_path} not found")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing config file: {e}")
        return []

async def store_message_text_standalone(message, channel_info, output_dir, logger, compliance_logger, error_logger):
    """Store plain message text in channel/date folder structure."""
    try:
        # Create channel-specific directory with date folder
        channel_dir = sanitize_filename(channel_info['title'])
        date_folder = message.date.strftime('%Y-%m-%d')
        message_path = os.path.join(output_dir, channel_dir, date_folder)
        os.makedirs(message_path, exist_ok=True)
        
        # Generate message text filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        message_filename = f"{timestamp}_msg_{message.id}_text.json"
        message_file_path = os.path.join(message_path, message_filename)
        
        # Prepare comprehensive message data
        message_data = {
            'channel_info': {
                'title': channel_info['title'],
                'username': channel_info.get('username'),
                'id': channel_info['id'],
                'parser': channel_info.get('parser', '')
            },
            'message_id': message.id,
            'date': message.date.isoformat(),
            'text': message.text or '',
            'views': getattr(message, 'views', 0),
            'forwards': getattr(message, 'forwards', 0),
            'replies': getattr(message, 'replies', None),
            'edit_date': message.edit_date.isoformat() if message.edit_date else None,
            'grouped_id': message.grouped_id,
            'from_id': str(message.from_id) if message.from_id else None,
            'via_bot_id': message.via_bot_id,
            'media_type': type(message.media).__name__ if message.media else None,
            'has_media': bool(message.media),
            'media_size': get_media_size(message) if message.media else 0,
            'collection_time': datetime.now().isoformat(),
            'folder_structure': f"{channel_dir}/{date_folder}"
        }
        
        # Write message data to JSON file
        with open(message_file_path, 'w', encoding='utf-8') as f:
            json.dump(message_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Stored message text: {message_file_path}")
        compliance_logger.info(f"MESSAGE_TEXT_STANDALONE: File={message_file_path}, MessageID={message.id}, Channel={channel_info['title']}")
        
        return message_file_path
        
    except Exception as e:
        logger.error(f"Error storing standalone message text: {e}")
        error_logger.error(f"MESSAGE_TEXT_STANDALONE_ERROR: {str(e)}, MessageID={message.id}, Channel={channel_info['title']}")
        return None

async def setup_message_listener(client, channels, download_manager, workflow_orchestrator, args, logger, compliance_logger, error_logger):
    """Setup event handler for listening to new messages."""
    
    # Create channel ID to channel info mapping
    channel_mapping = {channel['id']: channel for channel in channels}
    
    @client.on(events.NewMessage)
    async def handler(event):
        """Handle new messages from monitored channels."""
        try:
            # Check if message is from a monitored channel
            if event.chat_id not in channel_mapping:
                return
            
            channel_info = channel_mapping[event.chat_id]
            message = event.message
            
            logger.info(f"New message received from {channel_info['title']}: ID={message.id}")
            compliance_logger.info(f"REALTIME_MESSAGE: Channel={channel_info['title']}, MessageID={message.id}, Date={message.date}")
            
            # Check if message already downloaded (enhanced with content checking)
            media_type = type(message.media).__name__ if message.media else None
            media_size = get_media_size(message) if message.media else None
            
            is_duplicate, duplicate_reason = is_message_already_downloaded_enhanced(
                channel_info, message.id, message.text or '', media_type, media_size, args.output
            )
            
            if is_duplicate:
                logger.info(f"Skipping duplicate message {message.id}: {duplicate_reason}")
                compliance_logger.info(f"DUPLICATE_SKIPPED: MessageID={message.id}, Reason={duplicate_reason}")
                return
            
            # Process the message
            message_data = {
                'channel_info': channel_info,
                'message_id': message.id,
                'date': message.date.isoformat(),
                'text': message.text or '',
                'media_type': None,
                'has_media': bool(message.media),
                'downloaded_files': [],
                'parser': channel_info.get('parser', '')
            }
            
            # Handle media downloads
            if message.media and not args.dry_run:
                media_type = type(message.media).__name__
                media_size = get_media_size(message)
                message_data['media_type'] = media_type
                message_data['media_size'] = media_size
                message_data['media_size_formatted'] = format_file_size(media_size)
                
                logger.info(f"Processing media: {media_type}, Size: {format_file_size(media_size)}")
                
                # Check size limits
                if args.max_file_size_bytes and media_size > args.max_file_size_bytes:
                    logger.warning(f"File too large ({format_file_size(media_size)}), skipping download")
                    message_data['download_skipped'] = True
                    message_data['skip_reason'] = f"File too large ({format_file_size(media_size)})"
                else:
                    # Download the file
                    download_id = await download_manager.add_download(
                        client, message, channel_info, logger, compliance_logger, error_logger, media_size
                    )
                    
                    # Wait for download to complete
                    await download_manager.wait_for_download(download_id)
                    
                    # Get download result
                    result = download_manager.download_results.get(download_id)
                    if result:
                        message_data['downloaded_files'] = [result]
                    
                    logger.info(f"Download completed: {download_id}")
            elif not message.media:
                # Store text-only message
                message_text_path = await store_message_text_standalone(
                    message, channel_info, args.output, logger, compliance_logger, error_logger
                )
                if message_text_path:
                    message_data['message_text_path'] = message_text_path
            
            # Note: Workflow processing is now handled automatically by the integrated download system
            # The download manager will queue workflow processing when downloads complete
            logger.info(f"Message {message.id} processed - workflow will be handled automatically by download system")
            
        except Exception as e:
            logger.error(f"Error processing real-time message: {e}")
            error_logger.error(f"REALTIME_ERROR: {str(e)}, MessageID={getattr(event.message, 'id', 'unknown')}")
    
    logger.info(f"Message listener setup complete for {len(channels)} channels")
    compliance_logger.info(f"REALTIME_LISTENER: Monitoring {len(channels)} channels for new messages")

async def get_messages_from_channel(client, channel_info, download_manager, args, logger, compliance_logger, error_logger):
    """Get messages from a specific channel with concurrent downloads."""
    try:
        logger.info(f"Getting {args.messages} message(s) from: {channel_info['title']}")
        compliance_logger.info(f"API_REQUEST: Getting channel entity for ID {channel_info['id']}")
        
        # Get channel entity by ID
        channel_entity = await client.get_entity(channel_info['id'])
        logger.debug(f"Channel entity retrieved: {channel_entity.title}")
        
        # Get messages (limit=args.messages)
        compliance_logger.info(f"API_REQUEST: Getting messages from channel {channel_info['title']} (limit={args.messages})")
        messages = await client.get_messages(channel_entity, limit=args.messages)
        
        if not messages:
            logger.warning(f"No messages found in channel: {channel_info['title']}")
            compliance_logger.warning(f"EMPTY_CHANNEL: No messages found in {channel_info['title']}")
            return []
        
        logger.info(f"Retrieved {len(messages)} message(s) from {channel_info['title']}")
        
        processed_messages = []
        download_ids = []
        
        for i, message in enumerate(messages, 1):
            logger.debug(f"Processing message {i}/{len(messages)}: ID={message.id}, Date={message.date}, HasMedia={bool(message.media)}")
            
            # Extract message data
            message_data = {
                'channel_info': channel_info,
                'message_id': message.id,
                'date': message.date.isoformat(),
                'text': message.text or '',
                'media_type': None,
                'has_media': bool(message.media),
                'downloaded_files': [],
                'parser': channel_info.get('parser', '')
            }
            
            compliance_logger.info(f"MESSAGE_COLLECTED: Channel={channel_info['title']}, MessageID={message.id}, Date={message.date}")
            
            # Check if message already downloaded (enhanced with content checking)
            media_type = type(message.media).__name__ if message.media else None
            media_size = get_media_size(message) if message.media else None
            
            is_duplicate, duplicate_reason = is_message_already_downloaded_enhanced(
                channel_info, message.id, message.text or '', media_type, media_size, args.output
            )
            
            if is_duplicate:
                logger.info(f"Skipping duplicate message {message.id}: {duplicate_reason}")
                compliance_logger.info(f"DUPLICATE_SKIPPED: MessageID={message.id}, Reason={duplicate_reason}")
                message_data['duplicate_skipped'] = True
                message_data['skip_reason'] = duplicate_reason
                processed_messages.append(message_data)
                continue
            
            # Check for media and queue downloads
            if message.media and not args.dry_run:
                media_type = type(message.media).__name__
                media_size = get_media_size(message)
                message_data['media_type'] = media_type
                message_data['media_size'] = media_size
                message_data['media_size_formatted'] = format_file_size(media_size)
                
                logger.info(f"Message has media: {media_type}, Size: {format_file_size(media_size)}")
                compliance_logger.info(f"MEDIA_DETECTED: Type={media_type}, Size={media_size}, MessageID={message.id}")
                
                # Check size limits before queuing download
                should_skip = False
                if args.max_file_size_bytes and media_size > args.max_file_size_bytes:
                    logger.warning(f"File too large ({format_file_size(media_size)}), skipping download")
                    compliance_logger.warning(f"DOWNLOAD_SKIPPED: File too large - {media_size} bytes > {args.max_file_size_bytes} bytes")
                    message_data['download_skipped'] = True
                    message_data['skip_reason'] = f"File too large ({format_file_size(media_size)})"
                    should_skip = True
                
                if not should_skip:
                    # Add download to queue (non-blocking)
                    download_id = await download_manager.add_download(
                        client, message, channel_info, logger, compliance_logger, error_logger, media_size
                    )
                    download_ids.append(download_id)
                    message_data['download_ids'] = [download_id]  # Temporary field to track downloads
                    
                    logger.info(f"Download queued: {download_id} ({format_file_size(media_size)})")
                    compliance_logger.info(f"DOWNLOAD_QUEUED: ID={download_id}, Size={media_size}, MessageID={message.id}")
            elif message.media and args.dry_run:
                # In dry run mode, just show what would be downloaded
                media_type = type(message.media).__name__
                media_size = get_media_size(message)
                message_data['media_type'] = media_type
                message_data['media_size'] = media_size
                message_data['media_size_formatted'] = format_file_size(media_size)
                logger.info(f"[DRY RUN] Would download: {media_type}, Size: {format_file_size(media_size)}")
            else:
                # For messages without media, still store the message text
                if not args.dry_run:
                    logger.info("Message has no media, storing message text only")
                    message_text_path = await store_message_text_standalone(
                        message, channel_info, args.output, logger, compliance_logger, error_logger
                    )
                    if message_text_path:
                        message_data['message_text_path'] = message_text_path
                        compliance_logger.info(f"TEXT_ONLY_MESSAGE_STORED: Path={message_text_path}, MessageID={message.id}")
                else:
                    logger.info("[DRY RUN] Would store text-only message")
            
            processed_messages.append(message_data)
        
        return processed_messages, download_ids
        
    except ChannelPrivateError:
        logger.error(f"Channel is private: {channel_info['title']}")
        error_logger.error(f"PRIVATE_CHANNEL_ERROR: {channel_info['title']} (ID: {channel_info['id']})")
        compliance_logger.error(f"ACCESS_DENIED: Channel {channel_info['title']} is private")
        return [], []
    except FloodWaitError as e:
        logger.warning(f"Rate limited, waiting {e.seconds} seconds...")
        compliance_logger.warning(f"RATE_LIMIT: Waiting {e.seconds} seconds for channel {channel_info['title']}")
        await asyncio.sleep(e.seconds)
        return await get_messages_from_channel(client, channel_info, download_manager, args, logger, compliance_logger, error_logger)
    except Exception as e:
        logger.error(f"Error processing channel {channel_info['title']}: {e}")
        error_logger.error(f"CHANNEL_ERROR: {channel_info['title']} - {str(e)}")
        return [], []

async def main_process(args):
    """Main processing function."""
    # Setup logging
    logger, compliance_logger, error_logger = setup_dynamic_logging(args)
    
    logger.info("=== EntroSpies Infostealer Bot Started ===")
    compliance_logger.info("SESSION_START: Infostealer bot session initiated")
    
    if args.dry_run:
        logger.info("🔍 DRY RUN MODE: No files will be downloaded")
    
    # Log configuration
    mode = "listening for new messages" if args.listening_mode else f"downloading {args.messages} messages"
    logger.info(f"Configuration: Session={args.session}, Mode={mode}, Output={args.output}")
    if args.max_file_size_bytes:
        logger.info(f"File size limit: {format_file_size(args.max_file_size_bytes)}")
    
    # Load API credentials
    api_id, api_hash = load_api_credentials()
    logger.info("Loaded API credentials from environment variables or api_config.json")
    compliance_logger.info("API_CONFIG: Loaded credentials from environment or fallback file")
    
    # Load channels configuration
    channels = load_channels_config(args.config, logger, compliance_logger, args)
    if not channels:
        logger.error("No channels with specific parsers found")
        return
    
    # Create the client
    client = TelegramClient(args.session, api_id, api_hash)
    
    try:
        logger.info("Starting Telegram client...")
        compliance_logger.info("TELEGRAM_CONNECTION: Initiating client connection")
        await client.start()
        
        # Check if we're connected
        if not await client.is_user_authorized():
            logger.error("Not authorized. Please check your credentials.")
            error_logger.error("AUTHORIZATION_FAILED: Client not authorized")
            return
            
        logger.info("Successfully connected to Telegram!")
        
        # Get current user info
        me = await client.get_me()
        logger.info(f"Logged in as: {me.first_name} {me.last_name or ''} (@{me.username or 'no username'})")
        compliance_logger.info(f"USER_SESSION: UserID={me.id}, Username={me.username}, Phone={me.phone}")
        
        # Initialize master workflow orchestrator
        workflow_orchestrator = MasterWorkflowOrchestrator(
            base_download_dir=args.output,
            logger=logger
        )
        logger.info("Master workflow orchestrator initialized")
        compliance_logger.info("WORKFLOW_ORCHESTRATOR: Initialized for post-download processing")
        
        # Initialize enhanced download manager with workflow integration
        download_manager = DownloadManager(
            download_dir=args.output,
            workflow_orchestrator=workflow_orchestrator
        )
        download_workers = await download_manager.start_workers()
        
        logger.info(f"Started {len(download_workers)} download and workflow workers")
        compliance_logger.info(f"DOWNLOAD_MANAGER: Started {len(download_workers)} concurrent workers with workflow integration")
        
        # Handle listening mode vs batch mode
        if args.listening_mode:
            # Real-time listening mode
            logger.info("🔊 Starting real-time message listening mode")
            compliance_logger.info("LISTENING_MODE: Real-time message monitoring activated")
            
            # Setup message listener
            await setup_message_listener(
                client, channels, download_manager, workflow_orchestrator, args, logger, compliance_logger, error_logger
            )
            
            # Keep the client running
            logger.info("Bot is now listening for new messages. Press Ctrl+C to stop.")
            try:
                await client.run_until_disconnected()
            except KeyboardInterrupt:
                logger.info("Received shutdown signal, stopping message listener...")
                compliance_logger.info("LISTENING_MODE_STOPPED: User requested shutdown")
            
            return  # Exit early for listening mode
        
        # Batch processing mode (original behavior)
        logger.info("📦 Starting batch message processing mode")
        compliance_logger.info("BATCH_MODE: Processing historical messages")
        
        # Collect messages from each channel
        all_collected_messages = []
        all_download_ids = []
        
        try:
            for i, channel in enumerate(channels, 1):
                logger.info(f"Processing channel {i}/{len(channels)}: {channel['title']}")
                compliance_logger.info(f"CHANNEL_PROCESSING: {i}/{len(channels)} - {channel['title']} (ID: {channel['id']})")
                
                messages, download_ids = await get_messages_from_channel(
                    client, channel, download_manager, args, logger, compliance_logger, error_logger
                )
                
                if messages:
                    all_collected_messages.extend(messages)
                    all_download_ids.extend(download_ids)
                
                # Rate limiting compliance (1 second between requests)
                if i < len(channels):
                    logger.debug("Rate limiting delay...")
                    compliance_logger.info("RATE_LIMIT_DELAY: 1 second delay enforced")
                    await asyncio.sleep(1)
            
            # Wait for all downloads and workflows to complete
            if all_download_ids and not args.dry_run:
                logger.info(f"Waiting for {len(all_download_ids)} downloads and workflows to complete...")
                compliance_logger.info(f"DOWNLOAD_WAIT: Waiting for {len(all_download_ids)} downloads with integrated workflows")
                
                # Start progress monitoring
                print(f"\n📥 Starting {len(all_download_ids)} downloads with integrated workflow processing...")
                download_manager.start_progress_monitoring(len(all_download_ids))
                
                # Wait for both downloads and workflows to complete
                await download_manager.wait_for_all()
                
                # Ensure progress monitor is stopped
                download_manager.progress_monitor.stop_monitoring()
                print("✅ All downloads and workflows completed!")
                
                # Update message data with download results
                for message_data in all_collected_messages:
                    if message_data.get('download_ids'):
                        downloaded_files = []
                        workflow_results = []
                        for download_id in message_data['download_ids']:
                            # Get download result
                            result = download_manager.download_results.get(download_id)
                            if result:
                                downloaded_files.append(result)
                            
                            # Get workflow result
                            workflow_result = download_manager.workflow_results.get(f"workflow_{download_id}")
                            if workflow_result:
                                workflow_results.append(workflow_result)
                        
                        message_data['downloaded_files'] = downloaded_files
                        message_data['workflow_processing'] = workflow_results
                        del message_data['download_ids']  # Remove temporary field
                
                # Log integrated processing statistics
                download_stats = download_manager.get_download_statistics()
                logger.info(f"Integrated processing completed: {download_stats['download_stats']['completed']} downloads, {download_stats['workflow_results']} workflows processed")
                compliance_logger.info(f"INTEGRATED_STATS: Downloads={download_stats['download_stats']['completed']}, Workflows={download_stats['workflow_results']}, Failed={download_stats['download_stats']['failed']}")
                
                # Show priority distribution
                priority_stats = download_stats['priority_distribution']
                logger.info(f"Priority distribution: HIGH={priority_stats['HIGH']}, MEDIUM={priority_stats['MEDIUM']}, LOW={priority_stats['LOW']}")
                compliance_logger.info(f"PRIORITY_STATS: {priority_stats}")
        
        finally:
            # Shutdown download manager
            await download_manager.shutdown(download_workers)
            logger.info("Download manager shutdown completed")
        
        # Save results to JSON
        output_data = {
            'timestamp': datetime.now().isoformat(),
            'configuration': {
                'session': args.session,
                'messages_per_channel': args.messages,
                'max_file_size': args.max_file_size_bytes,
                'dry_run': args.dry_run,
                'channels_filter': args.channels_list,
                'exclude_filter': args.exclude_list
            },
            'total_channels_processed': len(channels),
            'total_messages_collected': len(all_collected_messages),
            'messages': all_collected_messages
        }
        
        if not args.dry_run:
            try:
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)
                logger.info(f"Results saved to {args.output_file}")
                compliance_logger.info(f"OUTPUT_SAVED: {args.output_file} - {len(all_collected_messages)} messages")
            except Exception as e:
                logger.error(f"Error saving results: {e}")
                error_logger.error(f"OUTPUT_ERROR: Failed to save {args.output_file} - {str(e)}")
        else:
            logger.info(f"[DRY RUN] Would save results to {args.output_file}")
        
        # Enhanced summary with detailed duplicate detection statistics
        downloads_count = sum(len(msg.get('downloaded_files', [])) for msg in all_collected_messages)
        duplicates_skipped = sum(1 for msg in all_collected_messages if msg.get('duplicate_skipped'))
        workflow_processed = sum(1 for msg in all_collected_messages if msg.get('workflow_processing'))
        workflow_successful = sum(1 for msg in all_collected_messages if msg.get('workflow_processing', {}).get('success'))
        
        # Count different types of duplicates
        id_duplicates = sum(1 for msg in all_collected_messages 
                           if msg.get('duplicate_skipped') and 'Message ID' in msg.get('skip_reason', ''))
        content_duplicates = sum(1 for msg in all_collected_messages 
                                if msg.get('duplicate_skipped') and 'Content duplicate' in msg.get('skip_reason', ''))
        
        logger.info(f"Summary: Channels processed: {len(channels)}, Messages collected: {len(all_collected_messages)}, Downloads completed: {downloads_count}, Duplicates skipped: {duplicates_skipped} (ID: {id_duplicates}, Content: {content_duplicates}), Workflow processed: {workflow_successful}/{workflow_processed}")
        compliance_logger.info(f"SESSION_SUMMARY: Processed={len(channels)}, Collected={len(all_collected_messages)}, Downloaded={downloads_count}, Duplicates={duplicates_skipped}, ID_Duplicates={id_duplicates}, Content_Duplicates={content_duplicates}, Workflow={workflow_successful}/{workflow_processed}")
        
    except SessionPasswordNeededError:
        logger.warning("Two-factor authentication is enabled. Please enter your password:")
        compliance_logger.warning("2FA_REQUIRED: Two-factor authentication needed")
        password = input("Password: ")
        await client.sign_in(password=password)
        logger.info("Successfully authenticated with 2FA!")
        compliance_logger.info("2FA_SUCCESS: Two-factor authentication completed")
        
    except Exception as e:
        logger.error(f"Error occurred: {e}")
        error_logger.error(f"CRITICAL_ERROR: {type(e).__name__} - {str(e)}")
        
    finally:
        await client.disconnect()
        logger.info("Disconnected from Telegram")
        compliance_logger.info("SESSION_END: Infostealer bot session completed")
        logger.info("=== EntroSpies Infostealer Bot Finished ===")

def main():
    """Main entry point."""
    # Parse command-line arguments
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    # Validate arguments
    args = validate_arguments(args)
    
    try:
        asyncio.run(main_process(args))
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()