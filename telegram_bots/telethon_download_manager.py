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

# Optimized download configuration for speed
MAX_CONCURRENT_DOWNLOADS = 5  # Increased for faster downloads
DOWNLOAD_RATE_LIMIT = 0.1  # Reduced delay for speed
DEFAULT_DOWNLOAD_DIR = 'download'

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

class FastProgressMonitor:
    """Minimal progress monitor optimized for speed."""
    
    def __init__(self, download_manager):
        self.download_manager = download_manager
        self.total_downloads = 0
        self.running = False
        
    def start_monitoring(self):
        """Minimal start - no threading for speed."""
        self.running = True
        
    def stop_monitoring(self):
        """Minimal stop."""
        self.running = False
    
    def set_total_downloads(self, total):
        """Set total downloads."""
        self.total_downloads = total

class TelethonDownloadManager:
    """Fast download manager using native telethon capabilities."""
    
    def __init__(self, download_dir=DEFAULT_DOWNLOAD_DIR, max_concurrent=MAX_CONCURRENT_DOWNLOADS, rate_limit=DOWNLOAD_RATE_LIMIT):
        self.download_dir = download_dir
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self.download_queue = asyncio.Queue()
        self.active_downloads = set()
        self.download_results = {}
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.progress_monitor = FastProgressMonitor(self)
        
    async def add_download(self, client, message, channel_info, logger, compliance_logger, error_logger, media_size=0):
        """Add a download task to the queue."""
        download_id = f"{channel_info['id']}_{message.id}"
        task_data = {
            'id': download_id,
            'client': client,
            'message': message,
            'channel_info': channel_info,
            'logger': logger,
            'compliance_logger': compliance_logger,
            'error_logger': error_logger,
            'media_size': media_size
        }
        await self.download_queue.put(task_data)
        return download_id
    
    async def download_worker(self):
        """Worker function to process downloads from queue."""
        while True:
            try:
                task = await self.download_queue.get()
                if task is None:
                    break
                
                download_id = task['id']
                
                async with self.semaphore:
                    self.active_downloads.add(download_id)
                    
                    # Rate limiting
                    await asyncio.sleep(self.rate_limit)
                    
                    # Perform download using telethon
                    result = await self._download_media_telethon(
                        task['client'], 
                        task['message'], 
                        task['channel_info'],
                        task['logger'],
                        task['compliance_logger'],
                        task['error_logger'],
                        task.get('media_size', 0)
                    )
                    
                    self.download_results[download_id] = result
                    self.active_downloads.discard(download_id)
                
                self.download_queue.task_done()
                
            except Exception as e:
                task['error_logger'].error(f"TELETHON_DOWNLOAD_WORKER_ERROR: {str(e)}")
                self.download_queue.task_done()
    
    async def _download_media_telethon(self, client, message, channel_info, logger, compliance_logger, error_logger, expected_size=0):
        """Fast download using telethon with minimal overhead."""
        try:
            # Create directory structure quickly
            channel_dir = sanitize_filename(channel_info['title'])
            date_folder = message.date.strftime('%Y-%m-%d')
            download_path = os.path.join(self.download_dir, channel_dir, date_folder)
            os.makedirs(download_path, exist_ok=True)
            
            # Store message text first (minimal version)
            message_text_path = await self._store_message_text_fast(message, channel_info, download_path)
            
            # Fast download with minimal progress tracking
            download_start_time = datetime.now()
            
            # Use telethon's native download_media method without progress callback for speed
            file_path = await message.download_media(file=download_path)
            
            if file_path:
                file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                download_duration = (datetime.now() - download_start_time).total_seconds()
                
                logger.info(f"Downloaded: {os.path.basename(file_path)} ({format_file_size(file_size)}) in {download_duration:.1f}s")
                
                return {
                    'file_path': file_path,
                    'file_size': file_size,
                    'download_duration': download_duration,
                    'message_text_path': message_text_path,
                    'message_attachment_paired': True
                }
            else:
                return {
                    'file_path': None,
                    'message_text_path': message_text_path,
                    'download_failed': True,
                    'message_attachment_paired': False
                }
                
        except Exception as e:
            logger.error(f"Download error: {e}")
            return None
    
    async def _store_message_text_fast(self, message, channel_info, download_path):
        """Fast message storage with minimal data."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            message_filename = f"{timestamp}_msg_{message.id}_message.json"
            message_file_path = os.path.join(download_path, message_filename)
            
            # Minimal message data for speed
            message_data = {
                'channel': channel_info['title'],
                'message_id': message.id,
                'date': message.date.isoformat(),
                'text': message.text or '',
                'has_media': bool(message.media),
                'parser': channel_info.get('parser', '')
            }
            
            with open(message_file_path, 'w', encoding='utf-8') as f:
                json.dump(message_data, f, ensure_ascii=False)
            
            return message_file_path
            
        except Exception:
            return None
    
    async def start_workers(self, num_workers=None):
        """Start download worker tasks."""
        if num_workers is None:
            num_workers = self.max_concurrent
        
        workers = []
        for i in range(num_workers):
            worker = asyncio.create_task(self.download_worker())
            workers.append(worker)
        
        return workers
    
    async def shutdown(self, workers):
        """Shutdown download workers and progress monitor."""
        self.progress_monitor.stop_monitoring()
        
        # Signal workers to stop
        for _ in workers:
            await self.download_queue.put(None)
        
        # Wait for workers to finish
        await asyncio.gather(*workers, return_exceptions=True)
    
    async def wait_for_downloads(self):
        """Wait for all downloads to complete."""
        await self.download_queue.join()
        
    def start_progress_monitoring(self, total_downloads):
        """Start progress monitoring with total download count."""
        self.progress_monitor.set_total_downloads(total_downloads)
        self.progress_monitor.start_monitoring()

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