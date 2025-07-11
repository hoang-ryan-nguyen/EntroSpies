#!/usr/bin/env python3
"""
Fast Telethon-based Download Manager for EntroSpies project.
Optimized for speed with minimal overhead.
"""

import asyncio
import os
import re
import json
from datetime import datetime
from telethon.tl.types import MessageMediaDocument, MessageMediaPhoto
import heapq
import threading
from typing import Dict, List, Optional, Any
from enum import Enum
from pathlib import Path

# Enhanced download configuration
MAX_CONCURRENT_DOWNLOADS = int(os.getenv('MAX_CONCURRENT_DOWNLOADS', 5))
DOWNLOAD_RATE_LIMIT = float(os.getenv('DOWNLOAD_RATE_LIMIT', 0.1))
DEFAULT_DOWNLOAD_DIR = os.getenv('DOWNLOAD_DIR', 'download')

# New configuration variables
MAX_WORKFLOW_THREADS = int(os.getenv('MAX_WORKFLOW_THREADS', 3))
DOWNLOAD_QUEUE_SIZE = int(os.getenv('DOWNLOAD_QUEUE_SIZE', 100))
WORKFLOW_QUEUE_SIZE = int(os.getenv('WORKFLOW_QUEUE_SIZE', 50))
DOWNLOAD_PRIORITY_ENABLED = os.getenv('DOWNLOAD_PRIORITY_ENABLED', 'true').lower() == 'true'
SMALL_FILE_PRIORITY_MB = int(os.getenv('SMALL_FILE_PRIORITY_MB', 10))
DEFAULT_CHANNEL_PRIORITY = os.getenv('DEFAULT_CHANNEL_PRIORITY', 'medium')

class DownloadPriority(Enum):
    """Download priority levels."""
    HIGH = 1      # Small files, critical channels
    MEDIUM = 2    # Medium files, normal channels
    LOW = 3       # Large files, background processing

def sanitize_filename(filename):
    """Sanitize filename for safe directory creation."""
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = re.sub(r'[\s\[\]{}()]+', '_', filename)
    filename = filename.strip('._')
    return filename[:50]

def get_media_size(message):
    """Get media file size before download."""
    if not message.media:
        return 0
    
    try:
        if isinstance(message.media, MessageMediaDocument):
            return message.media.document.size
        elif isinstance(message.media, MessageMediaPhoto):
            if hasattr(message.media.photo, 'sizes'):
                sizes = message.media.photo.sizes
                if sizes:
                    return max(getattr(size, 'size', 0) for size in sizes if hasattr(size, 'size'))
            return 0
        else:
            return 0
    except Exception:
        return 0

def format_file_size(size_bytes):
    """Format file size in human readable format."""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"

class DownloadTask:
    """Enhanced download task with priority and workflow support."""
    
    def __init__(self, download_id: str, priority: DownloadPriority, client, message, 
                 channel_info: Dict, logger, compliance_logger, error_logger, 
                 media_size: int = 0, workflow_orchestrator=None, channel_priority: str = "medium"):
        self.id = download_id
        self.priority = priority
        self.client = client
        self.message = message
        self.channel_info = channel_info
        self.logger = logger
        self.compliance_logger = compliance_logger
        self.error_logger = error_logger
        self.media_size = media_size
        self.workflow_orchestrator = workflow_orchestrator
        self.channel_priority = channel_priority  # high, medium, low from channel config
        self.created_at = datetime.now()
        self.started_at = None
        self.completed_at = None
        self.result = None
        self.status = "queued"  # queued, downloading, completed, failed
        
    def __lt__(self, other):
        """Compare tasks for priority queue (lower priority value = higher priority)."""
        if self.priority.value != other.priority.value:
            return self.priority.value < other.priority.value
        # If same priority, prefer smaller files
        return self.media_size < other.media_size
    
    def get_priority_based_on_size(self) -> DownloadPriority:
        """Legacy method for backward compatibility."""
        return self.get_combined_priority()
    
    def get_combined_priority(self) -> DownloadPriority:
        """Determine priority based on both channel priority and file size."""
        if not DOWNLOAD_PRIORITY_ENABLED:
            return DownloadPriority.MEDIUM
        
        # Channel priority takes precedence
        if self.channel_priority == "high":
            base_priority = DownloadPriority.HIGH
        elif self.channel_priority == "low":
            base_priority = DownloadPriority.LOW
        else:  # medium or unknown
            base_priority = DownloadPriority.MEDIUM
        
        # File size can adjust priority within the same channel level
        # For high priority channels, keep high priority regardless of size
        if base_priority == DownloadPriority.HIGH:
            return DownloadPriority.HIGH
        
        # For medium/low priority channels, small files get a boost
        size_mb = self.media_size / (1024 * 1024)
        if size_mb <= SMALL_FILE_PRIORITY_MB and base_priority == DownloadPriority.MEDIUM:
            return DownloadPriority.HIGH  # Small files from medium channels get high priority
        
        return base_priority

class WorkflowTask:
    """Workflow processing task."""
    
    def __init__(self, task_id: str, message_data: Dict, workflow_orchestrator, logger):
        self.id = task_id
        self.message_data = message_data
        self.workflow_orchestrator = workflow_orchestrator
        self.logger = logger
        self.created_at = datetime.now()
        self.started_at = None
        self.completed_at = None
        self.result = None
        self.status = "queued"  # queued, processing, completed, failed

class EnhancedProgressMonitor:
    """Enhanced progress monitor with per-download tracking."""
    
    def __init__(self, download_manager):
        self.download_manager = download_manager
        self.total_downloads = 0
        self.completed_downloads = 0
        self.failed_downloads = 0
        self.running = False
        self.download_progress = {}  # download_id -> progress info
        
    def start_monitoring(self):
        """Start progress monitoring."""
        self.running = True
        
    def stop_monitoring(self):
        """Stop progress monitoring."""
        self.running = False
    
    def set_total_downloads(self, total):
        """Set total downloads."""
        self.total_downloads = total
        
    def update_download_progress(self, download_id: str, status: str, progress: float = 0.0):
        """Update progress for a specific download."""
        self.download_progress[download_id] = {
            'status': status,
            'progress': progress,
            'updated_at': datetime.now()
        }
        
    def get_overall_progress(self) -> Dict:
        """Get overall progress statistics."""
        return {
            'total': self.total_downloads,
            'completed': self.completed_downloads,
            'failed': self.failed_downloads,
            'active': len(self.download_manager.active_downloads),
            'queued': self.download_manager.download_queue.qsize(),
            'progress_percent': (self.completed_downloads / max(self.total_downloads, 1)) * 100
        }

class TelethonDownloadManager:
    """Enhanced download manager with priority queue and workflow integration."""
    
    def __init__(self, download_dir=DEFAULT_DOWNLOAD_DIR, max_concurrent=MAX_CONCURRENT_DOWNLOADS, 
                 rate_limit=DOWNLOAD_RATE_LIMIT, workflow_orchestrator=None):
        self.download_dir = download_dir
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self.workflow_orchestrator = workflow_orchestrator
        
        # Enhanced queue system
        self.download_queue = asyncio.PriorityQueue(maxsize=DOWNLOAD_QUEUE_SIZE)
        self.workflow_queue = asyncio.Queue(maxsize=WORKFLOW_QUEUE_SIZE)
        
        # Tracking and results
        self.active_downloads = set()
        self.download_results = {}
        self.workflow_results = {}
        self.download_tasks = {}  # download_id -> DownloadTask
        
        # Concurrency control
        self.download_semaphore = asyncio.Semaphore(max_concurrent)
        self.workflow_semaphore = asyncio.Semaphore(MAX_WORKFLOW_THREADS)
        
        # Enhanced progress monitoring
        self.progress_monitor = EnhancedProgressMonitor(self)
        
        # Workflow workers
        self.workflow_workers = []
        
    async def add_download(self, client, message, channel_info, logger, compliance_logger, error_logger, media_size=0):
        """Add a download task to the priority queue."""
        download_id = f"{channel_info['id']}_{message.id}"
        
        # Extract channel priority from channel_info
        channel_priority = channel_info.get('priority', DEFAULT_CHANNEL_PRIORITY)
        
        # Create download task with priority
        task = DownloadTask(
            download_id=download_id,
            priority=DownloadPriority.MEDIUM,  # Default priority, will be updated
            client=client,
            message=message,
            channel_info=channel_info,
            logger=logger,
            compliance_logger=compliance_logger,
            error_logger=error_logger,
            media_size=media_size,
            workflow_orchestrator=self.workflow_orchestrator,
            channel_priority=channel_priority
        )
        
        # Auto-assign priority based on channel priority and file size
        if DOWNLOAD_PRIORITY_ENABLED:
            task.priority = task.get_combined_priority()
        else:
            task.priority = DownloadPriority.MEDIUM
        
        # Store task for tracking
        self.download_tasks[download_id] = task
        
        # Add to priority queue
        await self.download_queue.put(task)
        
        # Update progress tracking
        self.progress_monitor.update_download_progress(download_id, "queued")
        
        logger.info(f"Download queued: {download_id} (Priority: {task.priority.name}, Channel: {channel_priority}, Size: {format_file_size(media_size)})")
        compliance_logger.info(f"DOWNLOAD_QUEUED: ID={download_id}, Priority={task.priority.name}, ChannelPriority={channel_priority}, Size={media_size}")
        
        return download_id
    
    async def download_worker(self):
        """Enhanced worker function to process downloads from priority queue."""
        while True:
            try:
                task = await self.download_queue.get()
                if task is None:
                    break
                
                download_id = task.id
                task.started_at = datetime.now()
                task.status = "downloading"
                
                async with self.download_semaphore:
                    self.active_downloads.add(download_id)
                    
                    # Update progress
                    self.progress_monitor.update_download_progress(download_id, "downloading")
                    
                    # Rate limiting
                    await asyncio.sleep(self.rate_limit)
                    
                    # Perform download using telethon with message ID tracking
                    task.logger.debug(f"Starting download for message ID {task.message.id}")
                    result = await self._download_media_telethon(
                        task.client, 
                        task.message, 
                        task.channel_info,
                        task.logger,
                        task.compliance_logger,
                        task.error_logger,
                        task.media_size
                    )
                    
                    # Update task and results
                    task.completed_at = datetime.now()
                    task.result = result
                    
                    if result and result.get('file_path'):
                        task.status = "completed"
                        self.download_results[download_id] = result
                        self.progress_monitor.update_download_progress(download_id, "completed", 100.0)
                        self.progress_monitor.completed_downloads += 1
                        
                        # Log successful message-file pairing
                        task.logger.info(f"Message-file pair completed: Message ID {task.message.id} -> {os.path.basename(result['file_path'])}")
                        
                        # Queue for workflow processing if orchestrator is available
                        if self.workflow_orchestrator and result.get('file_path'):
                            await self._queue_workflow_processing(task, result)
                    else:
                        task.status = "failed"
                        self.progress_monitor.update_download_progress(download_id, "failed")
                        self.progress_monitor.failed_downloads += 1
                    
                    self.active_downloads.discard(download_id)
                
                self.download_queue.task_done()
                
            except Exception as e:
                if 'task' in locals():
                    task.error_logger.error(f"DOWNLOAD_WORKER_ERROR: {str(e)}")
                    task.status = "failed"
                    self.progress_monitor.failed_downloads += 1
                    self.active_downloads.discard(download_id)
                self.download_queue.task_done()
    
    async def _download_media_telethon(self, client, message, channel_info, logger, compliance_logger, error_logger, expected_size=0):
        """Fast download using telethon with individual message folders and sequential processing."""
        try:
            # Create individual message folder structure
            channel_dir = sanitize_filename(channel_info['title'])
            date_folder = message.date.strftime('%Y-%m-%d')
            message_folder = f"msg_{message.id}"
            download_path = os.path.join(self.download_dir, channel_dir, date_folder, message_folder)
            os.makedirs(download_path, exist_ok=True)
            
            logger.info(f"Created message folder: {download_path}")
            
            # Sequential processing: 1. Store message JSON first
            message_text_path = await self._store_message_text_fast(message, channel_info, download_path)
            
            # Sequential processing: 2. Extract and save password
            password_file_path = await self._extract_and_save_password(message, message_text_path, download_path, logger)
            
            # Sequential processing: 3. Download attachments to message folder
            download_start_time = datetime.now()
            
            # Use telethon's native download_media method without progress callback for speed
            file_path = await message.download_media(file=download_path)
            
            if file_path:
                file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                download_duration = (datetime.now() - download_start_time).total_seconds()
                
                logger.info(f"Downloaded to message folder: {os.path.basename(file_path)} ({format_file_size(file_size)}) in {download_duration:.1f}s")
                
                # Sequential processing: 4. Auto-decompress if password is available
                extraction_result = await self._auto_decompress_if_password_available(file_path, password_file_path, download_path, logger)
                
                return {
                    'file_path': file_path,
                    'file_size': file_size,
                    'download_duration': download_duration,
                    'message_text_path': message_text_path,
                    'password_file_path': password_file_path,
                    'extraction_result': extraction_result,
                    'message_folder': download_path,
                    'message_attachment_paired': True,
                    'message_id': message.id,
                    'message_date': message.date.isoformat()
                }
            else:
                return {
                    'file_path': None,
                    'message_text_path': message_text_path,
                    'password_file_path': password_file_path,
                    'message_folder': download_path,
                    'download_failed': True,
                    'message_attachment_paired': False,
                    'message_id': message.id,
                    'message_date': message.date.isoformat()
                }
                
        except Exception as e:
            logger.error(f"Download error: {e}")
            return None
    
    async def _store_message_text_fast(self, message, channel_info, download_path):
        """Fast message storage in individual message folder."""
        try:
            # Simple filename since we're in a dedicated message folder
            message_filename = "message.json"
            message_file_path = os.path.join(download_path, message_filename)
            
            # Minimal message data for speed with enhanced traceability
            message_data = {
                'channel': channel_info['title'],
                'channel_id': channel_info['id'],
                'message_id': message.id,
                'date': message.date.isoformat(),
                'text': message.text or '',
                'has_media': bool(message.media),
                'parser': channel_info.get('parser', ''),
                'download_id': f"{channel_info['id']}_{message.id}",
                'filename_timestamp': msg_date
            }
            
            with open(message_file_path, 'w', encoding='utf-8') as f:
                json.dump(message_data, f, ensure_ascii=False)
            
            return message_file_path
            
        except Exception:
            return None
    
    async def _extract_and_save_password(self, message, message_text_path, download_path, logger):
        """Extract password from message text and save to password.json."""
        try:
            # Import password extractor
            from infostealer_parser.boxedpw.boxedpw_password_extractor import PasswordExtractor
            
            # Initialize password extractor
            extractor = PasswordExtractor(logger)
            
            # Extract password from message text
            password = extractor.extract_password(message.text or '')
            
            # Always create password.json file, even if no password found
            password_file_path = os.path.join(download_path, "password.json")
            
            password_data = {
                'message_id': message.id,
                'channel': message_text_path,  # Reference to message file
                'extracted_password': password,
                'has_password': password is not None,
                'extraction_timestamp': datetime.now().isoformat(),
                'message_text': message.text or ''
            }
            
            with open(password_file_path, 'w', encoding='utf-8') as f:
                json.dump(password_data, f, indent=2, ensure_ascii=False)
            
            if password:
                logger.info(f"Password extracted and saved: {password}")
            else:
                logger.info("No password found in message, saved empty password.json")
            
            return password_file_path
            
        except Exception as e:
            logger.error(f"Error extracting password: {e}")
            # Still create empty password file to maintain structure
            try:
                password_file_path = os.path.join(download_path, "password.json")
                empty_password_data = {
                    'message_id': message.id,
                    'extracted_password': None,
                    'has_password': False,
                    'extraction_error': str(e),
                    'extraction_timestamp': datetime.now().isoformat()
                }
                
                with open(password_file_path, 'w', encoding='utf-8') as f:
                    json.dump(empty_password_data, f, indent=2, ensure_ascii=False)
                
                return password_file_path
            except Exception:
                return None
    
    async def _auto_decompress_if_password_available(self, file_path, password_file_path, download_path, logger):
        """Auto-decompress archive if password is available."""
        try:
            # Check if downloaded file is an archive
            if not file_path or not os.path.exists(file_path):
                return {'attempted': False, 'reason': 'No file to decompress'}
            
            # Check if it's a supported archive format
            archive_extensions = {'.rar', '.zip', '.7z', '.tar', '.tar.gz', '.tgz'}
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext not in archive_extensions:
                return {'attempted': False, 'reason': f'Unsupported archive format: {file_ext}'}
            
            # Read password from password.json
            password = None
            if password_file_path and os.path.exists(password_file_path):
                try:
                    with open(password_file_path, 'r', encoding='utf-8') as f:
                        password_data = json.load(f)
                        password = password_data.get('extracted_password')
                except Exception as e:
                    logger.error(f"Error reading password file: {e}")
            
            if not password:
                return {'attempted': False, 'reason': 'No password available for decompression'}
            
            # Import archive decompressor
            from archive_decompressor import ArchiveDecompressor
            
            # Initialize decompressor
            decompressor = ArchiveDecompressor(logger=logger)
            
            # Create extraction directory
            extract_dir = os.path.join(download_path, f"{os.path.splitext(os.path.basename(file_path))[0]}_extracted")
            
            # Attempt decompression
            logger.info(f"Attempting auto-decompression with password: {password}")
            
            success, extracted_files = decompressor.extract_archive(
                file_path,
                download_path,
                password=password,
                create_subfolder=True
            )
            
            if success:
                logger.info(f"Successfully auto-decompressed {len(extracted_files)} files")
                return {
                    'attempted': True,
                    'success': True,
                    'extracted_files': extracted_files,
                    'extract_dir': extract_dir,
                    'password_used': password
                }
            else:
                logger.warning(f"Auto-decompression failed with password: {password}")
                return {
                    'attempted': True,
                    'success': False,
                    'error': 'Decompression failed',
                    'password_used': password
                }
                
        except Exception as e:
            logger.error(f"Error during auto-decompression: {e}")
            return {
                'attempted': True,
                'success': False,
                'error': str(e)
            }
    
    async def _queue_workflow_processing(self, download_task: DownloadTask, download_result: Dict):
        """Queue completed download for workflow processing."""
        try:
            # Prepare message data for workflow
            message_data = {
                'channel_info': download_task.channel_info,
                'message_id': download_task.message.id,
                'date': download_task.message.date.isoformat(),
                'text': download_task.message.text or '',
                'downloaded_files': [download_result],
                'parser': download_task.channel_info.get('parser', ''),
                'media_size': download_task.media_size,
                'download_duration': download_result.get('download_duration', 0)
            }
            
            # Create workflow task
            workflow_task = WorkflowTask(
                task_id=f"workflow_{download_task.id}",
                message_data=message_data,
                workflow_orchestrator=download_task.workflow_orchestrator,
                logger=download_task.logger
            )
            
            # Add to workflow queue
            await self.workflow_queue.put(workflow_task)
            
            download_task.logger.info(f"Workflow queued for download: {download_task.id}")
            download_task.compliance_logger.info(f"WORKFLOW_QUEUED: DownloadID={download_task.id}")
            
        except Exception as e:
            download_task.error_logger.error(f"WORKFLOW_QUEUE_ERROR: {str(e)}")
    
    async def workflow_worker(self):
        """Worker function to process workflow tasks."""
        while True:
            try:
                task = await self.workflow_queue.get()
                if task is None:
                    break
                
                task.started_at = datetime.now()
                task.status = "processing"
                
                async with self.workflow_semaphore:
                    task.logger.info(f"Processing workflow: {task.id}")
                    
                    # Process with workflow orchestrator
                    result = task.workflow_orchestrator.process_message(task.message_data)
                    
                    # Update task
                    task.completed_at = datetime.now()
                    task.result = result
                    task.status = "completed" if result.get('success') else "failed"
                    
                    # Store result
                    self.workflow_results[task.id] = result
                    
                    task.logger.info(f"Workflow completed: {task.id} (Success: {result.get('success', False)})")
                
                self.workflow_queue.task_done()
                
            except Exception as e:
                if 'task' in locals():
                    task.logger.error(f"WORKFLOW_WORKER_ERROR: {str(e)}")
                    task.status = "failed"
                self.workflow_queue.task_done()
    
    async def start_workers(self, num_workers=None):
        """Start download and workflow worker tasks."""
        if num_workers is None:
            num_workers = self.max_concurrent
        
        workers = []
        
        # Start download workers
        for i in range(num_workers):
            worker = asyncio.create_task(self.download_worker())
            workers.append(worker)
        
        # Start workflow workers if orchestrator is available
        if self.workflow_orchestrator:
            for i in range(MAX_WORKFLOW_THREADS):
                workflow_worker = asyncio.create_task(self.workflow_worker())
                workers.append(workflow_worker)
                self.workflow_workers.append(workflow_worker)
        
        return workers
    
    async def shutdown(self, workers):
        """Shutdown download and workflow workers and progress monitor."""
        self.progress_monitor.stop_monitoring()
        
        # Signal download workers to stop
        for _ in range(self.max_concurrent):
            await self.download_queue.put(None)
        
        # Signal workflow workers to stop
        for _ in range(MAX_WORKFLOW_THREADS):
            await self.workflow_queue.put(None)
        
        # Wait for all workers to finish
        await asyncio.gather(*workers, return_exceptions=True)
    
    async def wait_for_downloads(self):
        """Wait for all downloads to complete."""
        await self.download_queue.join()
    
    async def wait_for_workflows(self):
        """Wait for all workflow processing to complete."""
        await self.workflow_queue.join()
    
    async def wait_for_all(self):
        """Wait for both downloads and workflows to complete."""
        await self.download_queue.join()
        await self.workflow_queue.join()
    
    async def wait_for_download(self, download_id):
        """Wait for a specific download to complete."""
        while download_id in self.active_downloads:
            await asyncio.sleep(0.1)  # Check every 100ms
        return self.download_results.get(download_id)
        
    def start_progress_monitoring(self, total_downloads):
        """Start progress monitoring with total download count."""
        self.progress_monitor.set_total_downloads(total_downloads)
        self.progress_monitor.start_monitoring()
    
    def get_download_statistics(self) -> Dict:
        """Get comprehensive download statistics."""
        active_tasks = len(self.active_downloads)
        queued_downloads = self.download_queue.qsize()
        queued_workflows = self.workflow_queue.qsize()
        
        # Calculate priority distribution
        priority_stats = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for task in self.download_tasks.values():
            priority_stats[task.priority.name] += 1
        
        # Get progress stats
        progress_stats = self.progress_monitor.get_overall_progress()
        
        return {
            'download_stats': progress_stats,
            'active_downloads': active_tasks,
            'queued_downloads': queued_downloads,
            'queued_workflows': queued_workflows,
            'priority_distribution': priority_stats,
            'total_tasks': len(self.download_tasks),
            'workflow_results': len(self.workflow_results)
        }
    
    def get_task_details(self, download_id: str) -> Optional[Dict]:
        """Get detailed information about a specific download task."""
        task = self.download_tasks.get(download_id)
        if not task:
            return None
        
        return {
            'id': task.id,
            'status': task.status,
            'priority': task.priority.name,
            'channel_priority': task.channel_priority,
            'media_size': task.media_size,
            'media_size_formatted': format_file_size(task.media_size),
            'channel': task.channel_info.get('title', 'Unknown'),
            'created_at': task.created_at.isoformat(),
            'started_at': task.started_at.isoformat() if task.started_at else None,
            'completed_at': task.completed_at.isoformat() if task.completed_at else None,
            'duration': (task.completed_at - task.started_at).total_seconds() if task.completed_at and task.started_at else None
        }

# Maintain compatibility with existing code
DownloadManager = TelethonDownloadManager

# Legacy wrapper for backward compatibility
async def download_message_media(client, message, channel_info, logger, compliance_logger, error_logger):
    """Download media from a message (legacy wrapper for backward compatibility)."""
    manager = TelethonDownloadManager()
    workers = await manager.start_workers(1)
    
    try:
        download_id = await manager.add_download(client, message, channel_info, logger, compliance_logger, error_logger)
        await manager.wait_for_downloads()
        return manager.download_results.get(download_id)
    finally:
        await manager.shutdown(workers)