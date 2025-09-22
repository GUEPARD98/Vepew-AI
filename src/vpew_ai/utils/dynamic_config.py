"""
Dynamic configuration management for VPEW-AI
Allows runtime configuration updates without agent restart
"""

import json
import time
import threading
from pathlib import Path
from typing import Dict, Any, Optional, Callable
from datetime import datetime


class DynamicConfig:
    """Dynamic configuration manager with file watching and callbacks"""
    
    def __init__(self, config_path: str, check_interval: int = 5):
        """
        Initialize dynamic configuration manager
        
        Args:
            config_path: Path to configuration file
            check_interval: Seconds between configuration checks
        """
        self.config_path = Path(config_path)
        self.check_interval = check_interval
        self.last_modified = 0
        self.config_data = {}
        self.callbacks = []
        self.running = False
        self.watch_thread = None
        self.lock = threading.Lock()
        
        # Load initial configuration
        self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    self.config_data = json.load(f)
                self.last_modified = self.config_path.stat().st_mtime
                return self.config_data
            else:
                return {}
        except Exception as e:
            print(f"Error loading config: {e}")
            return {}
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)"""
        with self.lock:
            keys = key.split('.')
            value = self.config_data
            
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            
            return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value (supports dot notation)"""
        with self.lock:
            keys = key.split('.')
            config = self.config_data
            
            # Navigate to the parent of the target key
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            
            # Set the final value
            config[keys[-1]] = value
            
            # Save to file
            self._save_config()
    
    def _save_config(self) -> None:
        """Save configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config_data, f, indent=2)
            self.last_modified = self.config_path.stat().st_mtime
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def add_change_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Add callback for configuration changes"""
        self.callbacks.append(callback)
    
    def remove_change_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Remove configuration change callback"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def _notify_callbacks(self, old_config: Dict[str, Any], new_config: Dict[str, Any]) -> None:
        """Notify all callbacks of configuration changes"""
        for callback in self.callbacks:
            try:
                callback(new_config)
            except Exception as e:
                print(f"Error in config callback: {e}")
    
    def start_watching(self) -> None:
        """Start watching for configuration file changes"""
        if self.running:
            return
        
        self.running = True
        self.watch_thread = threading.Thread(target=self._watch_loop, daemon=True)
        self.watch_thread.start()
    
    def stop_watching(self) -> None:
        """Stop watching for configuration changes"""
        self.running = False
        if self.watch_thread:
            self.watch_thread.join(timeout=1.0)
    
    def _watch_loop(self) -> None:
        """Main watching loop"""
        while self.running:
            try:
                if self.config_path.exists():
                    current_modified = self.config_path.stat().st_mtime
                    
                    if current_modified > self.last_modified:
                        old_config = self.config_data.copy()
                        new_config = self._load_config()
                        
                        if old_config != new_config:
                            self._notify_callbacks(old_config, new_config)
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                print(f"Error in config watch loop: {e}")
                time.sleep(self.check_interval)
    
    def reload(self) -> Dict[str, Any]:
        """Manually reload configuration"""
        old_config = self.config_data.copy()
        new_config = self._load_config()
        
        if old_config != new_config:
            self._notify_callbacks(old_config, new_config)
        
        return new_config
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration data"""
        with self.lock:
            return self.config_data.copy()
    
    def update_from_dict(self, updates: Dict[str, Any]) -> None:
        """Update configuration from dictionary"""
        with self.lock:
            self._deep_update(self.config_data, updates)
            self._save_config()
    
    def _deep_update(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]) -> None:
        """Deep update dictionary"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value


class ConfigValidator:
    """Configuration validator with schema checking"""
    
    def __init__(self, schema: Dict[str, Any]):
        """
        Initialize configuration validator
        
        Args:
            schema: Configuration schema definition
        """
        self.schema = schema
    
    def validate(self, config: Dict[str, Any]) -> tuple[bool, list[str]]:
        """
        Validate configuration against schema
        
        Returns:
            (is_valid, list_of_errors)
        """
        errors = []
        self._validate_dict(config, self.schema, "", errors)
        return len(errors) == 0, errors
    
    def _validate_dict(self, config: Dict[str, Any], schema: Dict[str, Any], path: str, errors: list[str]) -> None:
        """Recursively validate configuration"""
        for key, expected_type in schema.items():
            full_path = f"{path}.{key}" if path else key
            
            if key not in config:
                errors.append(f"Missing required field: {full_path}")
                continue
            
            value = config[key]
            
            if isinstance(expected_type, dict):
                if isinstance(value, dict):
                    self._validate_dict(value, expected_type, full_path, errors)
                else:
                    errors.append(f"Expected dict for {full_path}, got {type(value).__name__}")
            elif isinstance(expected_type, type):
                if not isinstance(value, expected_type):
                    errors.append(f"Expected {expected_type.__name__} for {full_path}, got {type(value).__name__}")
            elif callable(expected_type):
                if not expected_type(value):
                    errors.append(f"Validation failed for {full_path}: {value}")


# Default VPEW-AI configuration schema
DEFAULT_SCHEMA = {
    "agent": {
        "endpoint_id": str,
        "collection_interval": int,
        "ml_threshold": float
    },
    "ml": {
        "enabled": bool,
        "anomaly_threshold": float
    },
    "logging": {
        "level": str,
        "file": str
    },
    "backend": {
        "enabled": bool,
        "url": str
    }
}


# Global dynamic config instance
_dynamic_config = None


def get_dynamic_config(config_path: str = "config.json") -> DynamicConfig:
    """Get or create global dynamic configuration instance"""
    global _dynamic_config
    if _dynamic_config is None:
        _dynamic_config = DynamicConfig(config_path)
    return _dynamic_config


def create_config_validator(schema: Dict[str, Any] = None) -> ConfigValidator:
    """Create configuration validator with default or custom schema"""
    if schema is None:
        schema = DEFAULT_SCHEMA
    return ConfigValidator(schema)
