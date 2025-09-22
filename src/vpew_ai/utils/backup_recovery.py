"""
Backup and Recovery System for VPEW-AI
Provides automatic backup and recovery of critical configurations and data
"""

import os
import json
import shutil
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import hashlib
import gzip
import threading

logger = logging.getLogger(__name__)

class BackupType(Enum):
    """Types of backups"""
    CONFIG = "config"
    MODELS = "models"
    LOGS = "logs"
    RULES = "rules"
    CERTIFICATES = "certificates"
    FULL = "full"

class BackupStatus(Enum):
    """Backup status"""
    SUCCESS = "success"
    FAILED = "failed"
    IN_PROGRESS = "in_progress"
    PARTIAL = "partial"

@dataclass
class BackupInfo:
    """Backup information"""
    backup_id: str
    backup_type: BackupType
    status: BackupStatus
    created_at: datetime
    size_bytes: int
    file_path: str
    checksum: str
    description: str = ""
    restored_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

class BackupRecoveryManager:
    """Backup and recovery management system"""
    
    def __init__(self, base_path: str = "C:\\ProgramData\\vpew-ai", max_backups: int = 10):
        self.base_path = Path(base_path)
        self.backup_path = self.base_path / "backups"
        self.max_backups = max_backups
        self.backup_info_file = self.backup_path / "backup_info.json"
        self.backup_lock = threading.Lock()
        
        # Critical paths to backup
        self.critical_paths = {
            BackupType.CONFIG: [
                "config.json",
                "config_backup.json"
            ],
            BackupType.MODELS: [
                "models/anomaly_detector.joblib",
                "models/threat_classifier.joblib"
            ],
            BackupType.LOGS: [
                "logs"
            ],
            BackupType.RULES: [
                "src/vpew_ai/rules/rules"
            ],
            BackupType.CERTIFICATES: [
                "certs"
            ]
        }
        
        # Initialize backup directory
        self._initialize_backup_directory()
        
        logger.info("Backup and recovery system initialized")
    
    def _initialize_backup_directory(self):
        """Initialize backup directory structure"""
        try:
            self.backup_path.mkdir(parents=True, exist_ok=True)
            
            # Create subdirectories for different backup types
            for backup_type in BackupType:
                type_dir = self.backup_path / backup_type.value
                type_dir.mkdir(exist_ok=True)
            
            # Load existing backup info
            self._load_backup_info()
            
        except Exception as e:
            logger.error(f"Failed to initialize backup directory: {e}")
    
    def _load_backup_info(self):
        """Load backup information from file"""
        self.backup_history: List[BackupInfo] = []
        
        if self.backup_info_file.exists():
            try:
                with open(self.backup_info_file, 'r') as f:
                    data = json.load(f)
                    for item in data:
                        backup_info = BackupInfo(
                            backup_id=item['backup_id'],
                            backup_type=BackupType(item['backup_type']),
                            status=BackupStatus(item['status']),
                            created_at=datetime.fromisoformat(item['created_at']),
                            size_bytes=item['size_bytes'],
                            file_path=item['file_path'],
                            checksum=item['checksum'],
                            description=item.get('description', ''),
                            restored_at=datetime.fromisoformat(item['restored_at']) if item.get('restored_at') else None
                        )
                        self.backup_history.append(backup_info)
                
                logger.info(f"Loaded {len(self.backup_history)} backup records")
            except Exception as e:
                logger.error(f"Failed to load backup info: {e}")
                self.backup_history = []
    
    def _save_backup_info(self):
        """Save backup information to file"""
        try:
            data = []
            for backup in self.backup_history:
                item = asdict(backup)
                item['backup_type'] = backup.backup_type.value
                item['status'] = backup.status.value
                item['created_at'] = backup.created_at.isoformat()
                if backup.restored_at:
                    item['restored_at'] = backup.restored_at.isoformat()
                data.append(item)
            
            with open(self.backup_info_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save backup info: {e}")
    
    def create_backup(self, backup_type: BackupType, description: str = "") -> Tuple[bool, str]:
        """Create a backup of specified type"""
        with self.backup_lock:
            try:
                backup_id = self._generate_backup_id(backup_type)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_filename = f"{backup_type.value}_{timestamp}_{backup_id[:8]}.tar.gz"
                backup_file_path = self.backup_path / backup_type.value / backup_filename
                
                logger.info(f"Creating {backup_type.value} backup: {backup_id}")
                
                # Create backup info
                backup_info = BackupInfo(
                    backup_id=backup_id,
                    backup_type=backup_type,
                    status=BackupStatus.IN_PROGRESS,
                    created_at=datetime.now(),
                    size_bytes=0,
                    file_path=str(backup_file_path),
                    checksum="",
                    description=description
                )
                
                self.backup_history.append(backup_info)
                
                # Perform backup
                success = self._perform_backup(backup_type, backup_file_path, backup_info)
                
                if success:
                    backup_info.status = BackupStatus.SUCCESS
                    logger.info(f"Backup created successfully: {backup_id}")
                else:
                    backup_info.status = BackupStatus.FAILED
                    logger.error(f"Backup failed: {backup_id}")
                
                self._save_backup_info()
                self._cleanup_old_backups()
                
                return success, backup_id
                
            except Exception as e:
                logger.error(f"Error creating backup: {e}")
                return False, ""
    
    def _perform_backup(self, backup_type: BackupType, backup_path: Path, backup_info: BackupInfo) -> bool:
        """Perform the actual backup operation"""
        try:
            if backup_type == BackupType.FULL:
                return self._backup_full(backup_path, backup_info)
            else:
                return self._backup_selective(backup_type, backup_path, backup_info)
        except Exception as e:
            logger.error(f"Error performing backup: {e}")
            return False
    
    def _backup_full(self, backup_path: Path, backup_info: BackupInfo) -> bool:
        """Create full system backup"""
        try:
            # Create temporary directory for backup contents
            temp_dir = self.backup_path / "temp" / backup_info.backup_id
            temp_dir.mkdir(parents=True, exist_ok=True)
            
            # Copy all critical paths
            for backup_type, paths in self.critical_paths.items():
                if backup_type == BackupType.FULL:
                    continue
                    
                type_dir = temp_dir / backup_type.value
                type_dir.mkdir(exist_ok=True)
                
                for path in paths:
                    source_path = self.base_path / path
                    if source_path.exists():
                        dest_path = type_dir / path
                        dest_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        if source_path.is_file():
                            shutil.copy2(source_path, dest_path)
                        else:
                            shutil.copytree(source_path, dest_path, dirs_exist_ok=True)
            
            # Create compressed archive
            shutil.make_archive(str(backup_path.with_suffix('')), 'gztar', temp_dir)
            
            # Calculate size and checksum
            backup_info.size_bytes = backup_path.stat().st_size
            backup_info.checksum = self._calculate_checksum(backup_path)
            
            # Clean up temp directory
            shutil.rmtree(temp_dir.parent)
            
            return True
            
        except Exception as e:
            logger.error(f"Error in full backup: {e}")
            return False
    
    def _backup_selective(self, backup_type: BackupType, backup_path: Path, backup_info: BackupInfo) -> bool:
        """Create selective backup for specific type"""
        try:
            if backup_type not in self.critical_paths:
                logger.error(f"Unknown backup type: {backup_type}")
                return False
            
            # Create temporary directory
            temp_dir = self.backup_path / "temp" / backup_info.backup_id
            temp_dir.mkdir(parents=True, exist_ok=True)
            
            # Copy specified paths
            for path in self.critical_paths[backup_type]:
                source_path = self.base_path / path
                if source_path.exists():
                    dest_path = temp_dir / path
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    if source_path.is_file():
                        shutil.copy2(source_path, dest_path)
                    else:
                        shutil.copytree(source_path, dest_path, dirs_exist_ok=True)
            
            # Create compressed archive
            shutil.make_archive(str(backup_path.with_suffix('')), 'gztar', temp_dir)
            
            # Calculate size and checksum
            backup_info.size_bytes = backup_path.stat().st_size
            backup_info.checksum = self._calculate_checksum(backup_path)
            
            # Clean up temp directory
            shutil.rmtree(temp_dir.parent)
            
            return True
            
        except Exception as e:
            logger.error(f"Error in selective backup: {backup_type}: {e}")
            return False
    
    def restore_backup(self, backup_id: str) -> bool:
        """Restore from backup"""
        with self.backup_lock:
            try:
                # Find backup info
                backup_info = None
                for backup in self.backup_history:
                    if backup.backup_id == backup_id:
                        backup_info = backup
                        break
                
                if not backup_info:
                    logger.error(f"Backup not found: {backup_id}")
                    return False
                
                if backup_info.status != BackupStatus.SUCCESS:
                    logger.error(f"Backup is not in success status: {backup_info.status}")
                    return False
                
                backup_path = Path(backup_info.file_path)
                if not backup_path.exists():
                    logger.error(f"Backup file not found: {backup_path}")
                    return False
                
                # Verify checksum
                current_checksum = self._calculate_checksum(backup_path)
                if current_checksum != backup_info.checksum:
                    logger.error(f"Backup checksum mismatch: {backup_id}")
                    return False
                
                logger.info(f"Restoring backup: {backup_id}")
                
                # Perform restore
                success = self._perform_restore(backup_info, backup_path)
                
                if success:
                    backup_info.restored_at = datetime.now()
                    self._save_backup_info()
                    logger.info(f"Backup restored successfully: {backup_id}")
                else:
                    logger.error(f"Backup restore failed: {backup_id}")
                
                return success
                
            except Exception as e:
                logger.error(f"Error restoring backup: {e}")
                return False
    
    def _perform_restore(self, backup_info: BackupInfo, backup_path: Path) -> bool:
        """Perform the actual restore operation"""
        try:
            # Create temporary directory for extraction
            temp_dir = self.backup_path / "temp" / f"restore_{backup_info.backup_id}"
            temp_dir.mkdir(parents=True, exist_ok=True)
            
            # Extract backup
            shutil.unpack_archive(backup_path, temp_dir, 'gztar')
            
            # Restore files
            if backup_info.backup_type == BackupType.FULL:
                # Restore all types
                for backup_type in self.critical_paths:
                    if backup_type == BackupType.FULL:
                        continue
                    self._restore_type(temp_dir / backup_type.value, backup_type)
            else:
                # Restore specific type
                self._restore_type(temp_dir, backup_info.backup_type)
            
            # Clean up temp directory
            shutil.rmtree(temp_dir.parent)
            
            return True
            
        except Exception as e:
            logger.error(f"Error performing restore: {e}")
            return False
    
    def _restore_type(self, source_dir: Path, backup_type: BackupType):
        """Restore files for specific backup type"""
        if not source_dir.exists():
            return
        
        for path in self.critical_paths[backup_type]:
            source_path = source_dir / path
            dest_path = self.base_path / path
            
            if source_path.exists():
                # Create backup of existing file
                if dest_path.exists():
                    backup_dest = dest_path.with_suffix(f"{dest_path.suffix}.backup.{int(time.time())}")
                    if dest_path.is_file():
                        shutil.copy2(dest_path, backup_dest)
                    else:
                        shutil.copytree(dest_path, backup_dest, dirs_exist_ok=True)
                
                # Restore file
                if source_path.is_file():
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source_path, dest_path)
                else:
                    shutil.copytree(source_path, dest_path, dirs_exist_ok=True)
                
                logger.debug(f"Restored: {path}")
    
    def _generate_backup_id(self, backup_type: BackupType) -> str:
        """Generate unique backup ID"""
        timestamp = int(time.time())
        random_part = hashlib.md5(f"{backup_type.value}_{timestamp}".encode()).hexdigest()[:8]
        return f"{backup_type.value}_{timestamp}_{random_part}"
    
    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate file checksum"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating checksum: {e}")
            return ""
    
    def _cleanup_old_backups(self):
        """Clean up old backups based on retention policy"""
        try:
            # Group backups by type
            backups_by_type = {}
            for backup in self.backup_history:
                if backup.status == BackupStatus.SUCCESS:
                    if backup.backup_type not in backups_by_type:
                        backups_by_type[backup.backup_type] = []
                    backups_by_type[backup.backup_type].append(backup)
            
            # Keep only the most recent backups for each type
            for backup_type, backups in backups_by_type.items():
                if len(backups) > self.max_backups:
                    # Sort by creation time (newest first)
                    backups.sort(key=lambda x: x.created_at, reverse=True)
                    
                    # Remove old backups
                    for old_backup in backups[self.max_backups:]:
                        try:
                            backup_file = Path(old_backup.file_path)
                            if backup_file.exists():
                                backup_file.unlink()
                            
                            self.backup_history.remove(old_backup)
                            logger.info(f"Cleaned up old backup: {old_backup.backup_id}")
                        except Exception as e:
                            logger.error(f"Error cleaning up backup {old_backup.backup_id}: {e}")
            
            self._save_backup_info()
            
        except Exception as e:
            logger.error(f"Error in cleanup: {e}")
    
    def list_backups(self, backup_type: Optional[BackupType] = None) -> List[BackupInfo]:
        """List available backups"""
        if backup_type:
            return [backup for backup in self.backup_history if backup.backup_type == backup_type]
        return self.backup_history.copy()
    
    def get_backup_info(self, backup_id: str) -> Optional[BackupInfo]:
        """Get information about specific backup"""
        for backup in self.backup_history:
            if backup.backup_id == backup_id:
                return backup
        return None
    
    def delete_backup(self, backup_id: str) -> bool:
        """Delete a backup"""
        try:
            backup_info = self.get_backup_info(backup_id)
            if not backup_info:
                logger.error(f"Backup not found: {backup_id}")
                return False
            
            # Delete backup file
            backup_file = Path(backup_info.file_path)
            if backup_file.exists():
                backup_file.unlink()
            
            # Remove from history
            self.backup_history.remove(backup_info)
            self._save_backup_info()
            
            logger.info(f"Deleted backup: {backup_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting backup: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get backup and recovery statistics"""
        stats = {
            'total_backups': len(self.backup_history),
            'successful_backups': len([b for b in self.backup_history if b.status == BackupStatus.SUCCESS]),
            'failed_backups': len([b for b in self.backup_history if b.status == BackupStatus.FAILED]),
            'backups_by_type': {},
            'total_size_bytes': 0,
            'oldest_backup': None,
            'newest_backup': None
        }
        
        # Calculate statistics by type
        for backup_type in BackupType:
            type_backups = [b for b in self.backup_history if b.backup_type == backup_type]
            stats['backups_by_type'][backup_type.value] = len(type_backups)
        
        # Calculate total size
        for backup in self.backup_history:
            if backup.status == BackupStatus.SUCCESS:
                stats['total_size_bytes'] += backup.size_bytes
        
        # Find oldest and newest backups
        if self.backup_history:
            sorted_backups = sorted(self.backup_history, key=lambda x: x.created_at)
            stats['oldest_backup'] = sorted_backups[0].created_at.isoformat()
            stats['newest_backup'] = sorted_backups[-1].created_at.isoformat()
        
        return stats
    
    def schedule_automatic_backup(self, backup_type: BackupType, interval_hours: int = 24):
        """Schedule automatic backups (placeholder for future implementation)"""
        logger.info(f"Scheduled automatic {backup_type.value} backup every {interval_hours} hours")

def get_backup_recovery_manager(base_path: str = "C:\\ProgramData\\vpew-ai") -> BackupRecoveryManager:
    """Get backup and recovery manager instance"""
    return BackupRecoveryManager(base_path)
