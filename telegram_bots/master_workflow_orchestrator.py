#!/usr/bin/env python3
"""
Master Workflow Orchestrator for EntroSpies project.
Controls and coordinates all infostealer channel workflows based on parser configuration.
"""

import os
import sys
import json
import logging
import importlib
import asyncio
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from datetime import datetime


class MasterWorkflowOrchestrator:
    """
    Master orchestrator that manages all infostealer channel workflows.
    Routes messages to appropriate workflow processors based on channel configuration.
    """
    
    def __init__(self, base_download_dir: str = "download", logger: Optional[logging.Logger] = None):
        """
        Initialize the master workflow orchestrator.
        
        Args:
            base_download_dir: Base directory for downloads
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        self.base_download_dir = Path(base_download_dir)
        
        # Registry of loaded workflow processors
        self.workflow_processors = {}
        
        # Workflow configuration mapping
        self.workflow_config = {
            'infostealer_parser/boxedpw/boxedpw_workflow.py': {
                'module_path': 'infostealer_parser.boxedpw.boxedpw_workflow',
                'class_name': 'BoxedPwWorkflow',
                'description': 'Boxed.pw channel workflow processor'
            }
            # Additional workflows can be added here as they are implemented
        }
        
        # Processing statistics
        self.stats = {
            'total_messages_processed': 0,
            'successful_processing': 0,
            'failed_processing': 0,
            'skipped_processing': 0,
            'workflow_stats': {}
        }
        
        self.logger.info("Master workflow orchestrator initialized")
    
    def register_workflow(self, parser_path: str, module_path: str, class_name: str, description: str = ""):
        """
        Register a workflow processor.
        
        Args:
            parser_path: Parser path as defined in config.json
            module_path: Python module path for the workflow
            class_name: Class name of the workflow processor
            description: Description of the workflow
        """
        self.workflow_config[parser_path] = {
            'module_path': module_path,
            'class_name': class_name,
            'description': description
        }
        self.logger.info(f"Registered workflow: {parser_path} -> {class_name}")
    
    def _load_workflow_processor(self, parser_path: str) -> Optional[Any]:
        """
        Load a workflow processor class dynamically.
        
        Args:
            parser_path: Parser path from channel configuration
            
        Returns:
            Workflow processor instance or None if loading failed
        """
        if parser_path in self.workflow_processors:
            return self.workflow_processors[parser_path]
        
        if parser_path not in self.workflow_config:
            self.logger.warning(f"No workflow configuration found for parser: {parser_path}")
            return None
        
        config = self.workflow_config[parser_path]
        
        try:
            # Import the module with proper error handling
            module = importlib.import_module(config['module_path'])
            
            # Get the class
            workflow_class = getattr(module, config['class_name'])
            
            # Create instance
            workflow_instance = workflow_class(
                base_download_dir=str(self.base_download_dir),
                logger=self.logger
            )
            
            # Cache the instance
            self.workflow_processors[parser_path] = workflow_instance
            
            self.logger.info(f"Loaded workflow processor: {config['class_name']} for {parser_path}")
            return workflow_instance
            
        except ImportError as e:
            self.logger.error(f"Failed to import workflow module {config['module_path']}: {e}")
            return None
        except AttributeError as e:
            self.logger.error(f"Workflow class {config['class_name']} not found in module: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error loading workflow processor for {parser_path}: {e}")
            return None
    
    def process_message(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single message using the appropriate workflow.
        
        Args:
            message_data: Message data dictionary with channel info and metadata
            
        Returns:
            Dictionary with processing results
        """
        start_time = datetime.now()
        
        # Initialize result structure
        result = {
            'success': False,
            'message_id': message_data.get('message_id'),
            'channel_title': message_data.get('channel_info', {}).get('title', 'Unknown'),
            'parser_path': message_data.get('parser', ''),
            'processing_time': 0,
            'workflow_used': None,
            'workflow_result': {},
            'errors': [],
            'warnings': []
        }
        
        try:
            self.stats['total_messages_processed'] += 1
            
            # Skip if message was marked as duplicate
            if message_data.get('duplicate_skipped'):
                result['skipped'] = True
                result['skip_reason'] = message_data.get('skip_reason', 'Duplicate')
                self.stats['skipped_processing'] += 1
                self.logger.debug(f"Skipping duplicate message {message_data.get('message_id')}")
                return result
            
            # Get parser path from message data
            parser_path = message_data.get('parser', '')
            if not parser_path:
                result['errors'].append("No parser path specified in message data")
                self.logger.warning(f"No parser path for message {message_data.get('message_id')}")
                self.stats['failed_processing'] += 1
                return result
            
            # Check if parser path is supported
            if parser_path not in self.workflow_config:
                result['warnings'].append(f"No workflow available for parser: {parser_path}")
                self.logger.warning(f"No workflow configuration for parser: {parser_path}")
                self.stats['skipped_processing'] += 1
                return result
            
            # Load workflow processor
            workflow_processor = self._load_workflow_processor(parser_path)
            if not workflow_processor:
                result['errors'].append(f"Failed to load workflow processor for: {parser_path}")
                self.logger.error(f"Failed to load workflow processor for: {parser_path}")
                self.stats['failed_processing'] += 1
                return result
            
            result['workflow_used'] = self.workflow_config[parser_path]['class_name']
            
            # Extract required parameters for workflow
            channel_info = message_data.get('channel_info', {})
            message_id = message_data.get('message_id')
            message_date = message_data.get('date', datetime.now().isoformat())
            
            # Create date folder from message date
            try:
                if isinstance(message_date, str):
                    date_obj = datetime.fromisoformat(message_date.replace('Z', '+00:00'))
                else:
                    date_obj = message_date
                date_folder = date_obj.strftime('%Y-%m-%d')
            except Exception:
                date_folder = datetime.now().strftime('%Y-%m-%d')
            
            # Build channel directory path
            channel_dir = self.base_download_dir / self._sanitize_filename(channel_info.get('title', 'unknown'))
            
            self.logger.info(f"Processing message {message_id} with {result['workflow_used']} workflow")
            
            # Call workflow processor
            workflow_result = workflow_processor.process_download(
                channel_dir=str(channel_dir),
                date_folder=date_folder,
                message_id=message_id,
                message_data=message_data
            )
            
            result['workflow_result'] = workflow_result
            result['success'] = workflow_result.get('success', False)
            
            # Aggregate errors and warnings
            if workflow_result.get('errors'):
                result['errors'].extend(workflow_result['errors'])
            if workflow_result.get('warnings'):
                result['warnings'].extend(workflow_result['warnings'])
            
            # Update statistics
            if result['success']:
                self.stats['successful_processing'] += 1
            else:
                self.stats['failed_processing'] += 1
            
            # Track workflow-specific stats
            workflow_name = result['workflow_used']
            if workflow_name not in self.stats['workflow_stats']:
                self.stats['workflow_stats'][workflow_name] = {
                    'processed': 0,
                    'successful': 0,
                    'failed': 0
                }
            
            self.stats['workflow_stats'][workflow_name]['processed'] += 1
            if result['success']:
                self.stats['workflow_stats'][workflow_name]['successful'] += 1
            else:
                self.stats['workflow_stats'][workflow_name]['failed'] += 1
            
        except Exception as e:
            self.logger.error(f"Error processing message {message_data.get('message_id')}: {e}")
            result['errors'].append(f"Processing error: {str(e)}")
            self.stats['failed_processing'] += 1
        
        finally:
            result['processing_time'] = (datetime.now() - start_time).total_seconds()
        
        return result
    
    def process_messages_batch(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process multiple messages in batch.
        
        Args:
            messages: List of message data dictionaries
            
        Returns:
            List of processing results
        """
        self.logger.info(f"Processing batch of {len(messages)} messages")
        
        results = []
        for message_data in messages:
            try:
                result = self.process_message(message_data)
                results.append(result)
                
                # Log progress for large batches
                if len(results) % 10 == 0:
                    self.logger.debug(f"Processed {len(results)}/{len(messages)} messages")
                    
            except Exception as e:
                self.logger.error(f"Error in batch processing: {e}")
                # Create error result
                error_result = {
                    'success': False,
                    'message_id': message_data.get('message_id', 'unknown'),
                    'errors': [f"Batch processing error: {str(e)}"],
                    'processing_time': 0
                }
                results.append(error_result)
        
        self.logger.info(f"Completed batch processing: {len(results)} results")
        return results
    
    def get_processing_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive processing statistics.
        
        Returns:
            Dictionary with processing statistics
        """
        total_processed = self.stats['total_messages_processed']
        success_rate = 0
        if total_processed > 0:
            success_rate = (self.stats['successful_processing'] / total_processed) * 100
        
        return {
            'total_messages_processed': total_processed,
            'successful_processing': self.stats['successful_processing'],
            'failed_processing': self.stats['failed_processing'],
            'skipped_processing': self.stats['skipped_processing'],
            'success_rate_percent': round(success_rate, 2),
            'workflow_statistics': self.stats['workflow_stats'].copy(),
            'registered_workflows': list(self.workflow_config.keys()),
            'loaded_processors': list(self.workflow_processors.keys())
        }
    
    def get_supported_parsers(self) -> List[str]:
        """
        Get list of supported parser paths.
        
        Returns:
            List of supported parser paths
        """
        return list(self.workflow_config.keys())
    
    def is_parser_supported(self, parser_path: str) -> bool:
        """
        Check if a parser path is supported.
        
        Args:
            parser_path: Parser path to check
            
        Returns:
            True if supported, False otherwise
        """
        return parser_path in self.workflow_config
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe directory creation."""
        import re
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        filename = re.sub(r'[\s\[\]{}()]+', '_', filename)
        filename = filename.strip('._')
        return filename[:50]  # Limit length
    
    def reset_statistics(self):
        """Reset all processing statistics."""
        self.stats = {
            'total_messages_processed': 0,
            'successful_processing': 0,
            'failed_processing': 0,
            'skipped_processing': 0,
            'workflow_stats': {}
        }
        self.logger.info("Processing statistics reset")
    
    def get_workflow_status(self) -> Dict[str, Any]:
        """
        Get current orchestrator status.
        
        Returns:
            Dictionary with orchestrator status
        """
        return {
            'base_download_dir': str(self.base_download_dir),
            'registered_workflows': len(self.workflow_config),
            'loaded_processors': len(self.workflow_processors),
            'supported_parsers': self.get_supported_parsers(),
            'processing_stats': self.get_processing_statistics()
        }


def main():
    """
    Command-line interface for testing the master workflow orchestrator.
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Test master workflow orchestrator')
    parser.add_argument('--download-dir', default='download', help='Download directory')
    parser.add_argument('--test-message', action='store_true', help='Test with sample message')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    
    # Create orchestrator
    orchestrator = MasterWorkflowOrchestrator(
        base_download_dir=args.download_dir
    )
    
    if args.test_message:
        # Test with sample message data
        sample_message = {
            'channel_info': {
                'title': 'Test Channel',
                'id': 1935880746
            },
            'message_id': 12345,
            'date': datetime.now().isoformat(),
            'text': '[🔑 .pass:](https://t.me/c/1935880746/28) ```@LOGACTIVE```',
            'parser': 'infostealer_parser/boxedpw/boxedpw_workflow.py',
            'has_media': True,
            'downloaded_files': [
                {'file_path': '/test/path/file.rar', 'success': True, 'file_size': 1024000}
            ]
        }
        
        print("Testing with sample message...")
        result = orchestrator.process_message(sample_message)
        
        print("\nProcessing Result:")
        print("=" * 50)
        print(f"Success: {result['success']}")
        print(f"Workflow Used: {result['workflow_used']}")
        print(f"Processing Time: {result['processing_time']:.2f}s")
        
        if result.get('errors'):
            print(f"Errors: {result['errors']}")
        if result.get('warnings'):
            print(f"Warnings: {result['warnings']}")
    
    if args.stats:
        # Show statistics
        stats = orchestrator.get_processing_statistics()
        
        print("\nOrchestrator Statistics:")
        print("=" * 50)
        print(f"Total Processed: {stats['total_messages_processed']}")
        print(f"Successful: {stats['successful_processing']}")
        print(f"Failed: {stats['failed_processing']}")
        print(f"Skipped: {stats['skipped_processing']}")
        print(f"Success Rate: {stats['success_rate_percent']}%")
        
        if stats['workflow_statistics']:
            print("\nWorkflow Statistics:")
            for workflow, workflow_stats in stats['workflow_statistics'].items():
                print(f"  {workflow}: {workflow_stats['successful']}/{workflow_stats['processed']} successful")
    
    # Show status
    status = orchestrator.get_workflow_status()
    print(f"\nOrchestrator Status:")
    print("=" * 50)
    print(f"Download Directory: {status['base_download_dir']}")
    print(f"Registered Workflows: {status['registered_workflows']}")
    print(f"Loaded Processors: {status['loaded_processors']}")
    print(f"Supported Parsers: {status['supported_parsers']}")


if __name__ == "__main__":
    main()