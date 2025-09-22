#!/usr/bin/env python3
"""
Feature Extractor
Converts raw Windows events into ML-ready feature vectors
"""

import logging
import hashlib
import re
import numpy as np
from typing import Dict, List, Optional, Union, Any
from datetime import datetime
import ipaddress

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """
    Extract ML features from Windows security events
    
    Converts raw event data into numerical features suitable for
    machine learning models (anomaly detection, classification)
    """
    
    # Common Windows processes for baseline behavior
    COMMON_PROCESSES = {
        "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
        "dwm.exe", "taskhost.exe", "rundll32.exe", "dllhost.exe"
    }
    
    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", 
        ".js", ".jar", ".ps1", ".msi", ".dll"
    }
    
    # Network ports commonly used by malware
    SUSPICIOUS_PORTS = {
        1337, 31337, 4444, 5555, 6666, 7777, 8888, 9999,
        12345, 54321, 65534, 4443, 8443
    }
    
    def __init__(self):
        """Initialize feature extractor"""
        self.process_baseline = {}
        self.network_baseline = {}
        self.user_baseline = {}
        
        logger.info("Feature extractor initialized")
    
    def extract(self, event: Dict) -> Optional[Dict]:
        """
        Extract features from a single event
        
        Args:
            event: Raw event dictionary
            
        Returns:
            Dictionary with extracted features or None if extraction fails
        """
        try:
            # Generate fixed set of features for ML compatibility
            features = self._extract_fixed_features(event)
            
            # Convert to numpy array for ML models
            feature_vector = np.array(list(features.values()), dtype=np.float32)
            
            return {
                "feature_vector": feature_vector,
                "feature_names": list(features.keys()),
                "raw_features": features
            }
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None
    
    def _extract_fixed_features(self, event: Dict) -> Dict[str, float]:
        """
        Extract a fixed set of features for ML compatibility
        
        Returns exactly 25 features to match training data
        """
        # Basic event features
        event_id = float(event.get("event_id", 0))
        log_type = self._encode_log_type(event.get("log_type", "unknown"))
        
        # Process features
        process_name = event.get("process_name", "")
        command_line = event.get("command_line", "")
        process_id = float(event.get("process_id", 0))
        
        # Network features
        remote_ip = event.get("remote_ip", "")
        remote_port = float(event.get("remote_port", 0))
        local_port = float(event.get("local_port", 0))
        
        # User features
        user_name = event.get("user_name", "")
        session_id = float(event.get("session_id", 0))
        
        # File features
        file_path = event.get("file_path", "")
        file_size = float(event.get("file_size", 0))
        
        # Registry features
        registry_path = event.get("registry_path", "")
        
        # Behavioral features
        entropy = self._calculate_entropy(command_line)
        suspicious_process = 1.0 if any(susp in process_name.lower() for susp in ["powershell", "cmd", "rundll32"]) else 0.0
        suspicious_port = 1.0 if remote_port in self.SUSPICIOUS_PORTS else 0.0
        encoded_command = 1.0 if any(enc in command_line.lower() for enc in ["-enc", "-e ", "-encodedcommand"]) else 0.0
        
        # Risk indicators
        external_ip = 1.0 if self._is_external_ip(remote_ip) else 0.0
        system_process = 1.0 if process_name.lower() in self.COMMON_PROCESSES else 0.0
        suspicious_extension = 1.0 if any(ext in file_path.lower() for ext in self.SUSPICIOUS_EXTENSIONS) else 0.0
        
        # Time features
        timestamp = event.get("timestamp", 0)
        hour = float(datetime.fromtimestamp(timestamp).hour if timestamp else 12)
        day_of_week = float(datetime.fromtimestamp(timestamp).weekday() if timestamp else 0)
        
        # Return exactly 25 features
        return {
            "feature_0": event_id,
            "feature_1": log_type,
            "feature_2": process_id,
            "feature_3": remote_port,
            "feature_4": local_port,
            "feature_5": session_id,
            "feature_6": file_size,
            "feature_7": entropy,
            "feature_8": suspicious_process,
            "feature_9": suspicious_port,
            "feature_10": encoded_command,
            "feature_11": external_ip,
            "feature_12": system_process,
            "feature_13": suspicious_extension,
            "feature_14": hour,
            "feature_15": day_of_week,
            "feature_16": len(process_name),
            "feature_17": len(command_line),
            "feature_18": len(user_name),
            "feature_19": len(file_path),
            "feature_20": len(registry_path),
            "feature_21": 1.0 if "admin" in user_name.lower() else 0.0,
            "feature_22": 1.0 if "system" in user_name.lower() else 0.0,
            "feature_23": 1.0 if "temp" in file_path.lower() else 0.0,
            "feature_24": 1.0 if "download" in file_path.lower() else 0.0
        }
    
    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external (not private/loopback)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback)
        except:
            return False
    
    def _encode_log_type(self, log_type: str) -> int:
        """Encode log type as numerical value"""
        log_type_map = {
            "security": 1,
            "system": 2,
            "application": 3,
            "sysmon": 4,
            "etw": 5,
            "unknown": 0
        }
        return log_type_map.get(log_type.lower(), 0)
    
    def _extract_temporal_features(self, event: Dict) -> Dict:
        """Extract time-based features"""
        features = {}
        
        try:
            # Parse timestamp
            timestamp_str = event.get("time_generated") or event.get("timestamp")
            if timestamp_str:
                if isinstance(timestamp_str, str):
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                else:
                    timestamp = datetime.fromtimestamp(timestamp_str)
                
                # Extract temporal features
                features.update({
                    "hour_of_day": timestamp.hour,
                    "day_of_week": timestamp.weekday(),
                    "is_weekend": int(timestamp.weekday() >= 5),
                    "is_business_hours": int(9 <= timestamp.hour <= 17),
                    "is_night_time": int(timestamp.hour < 6 or timestamp.hour > 22)
                })
            else:
                # Default values if no timestamp
                features.update({
                    "hour_of_day": 0,
                    "day_of_week": 0,
                    "is_weekend": 0,
                    "is_business_hours": 1,
                    "is_night_time": 0
                })
                
        except Exception as e:
            logger.debug(f"Error extracting temporal features: {e}")
            features = {
                "hour_of_day": 0, "day_of_week": 0, "is_weekend": 0,
                "is_business_hours": 1, "is_night_time": 0
            }
        
        return features
    
    def _extract_process_features(self, event: Dict) -> Dict:
        """Extract process-related features"""
        features = {}
        
        # Process name/image
        image = event.get("image") or event.get("process_name", "")
        if image:
            process_name = image.lower().split("\\")[-1]
            features.update({
                "is_common_process": int(process_name in self.COMMON_PROCESSES),
                "process_name_length": len(process_name),
                "has_suspicious_name": int(self._is_suspicious_process_name(process_name)),
                "process_name_hash": self._hash_string(process_name) % 1000
            })
        else:
            features.update({
                "is_common_process": 0, "process_name_length": 0,
                "has_suspicious_name": 0, "process_name_hash": 0
            })
        
        # Command line analysis
        cmdline = event.get("commandline") or event.get("command_line", "")
        if cmdline:
            features.update({
                "cmdline_length": len(cmdline),
                "has_powershell": int("powershell" in cmdline.lower()),
                "has_encoded_command": int("-enc" in cmdline.lower() or "-e " in cmdline.lower()),
                "has_download_command": int(any(cmd in cmdline.lower() for cmd in ["wget", "curl", "invoke-webrequest", "downloadstring"])),
                "cmdline_entropy": self._calculate_entropy(cmdline)
            })
        else:
            features.update({
                "cmdline_length": 0, "has_powershell": 0, "has_encoded_command": 0,
                "has_download_command": 0, "cmdline_entropy": 0
            })
        
        # Process IDs
        features.update({
            "process_id": int(event.get("processid") or event.get("process_id", 0)),
            "parent_process_id": int(event.get("parentprocessid") or event.get("parent_process_id", 0))
        })
        
        return features
    
    def _extract_network_features(self, event: Dict) -> Dict:
        """Extract network-related features"""
        features = {
            "has_network_activity": 0,
            "is_outbound_connection": 0,
            "is_suspicious_port": 0,
            "is_private_ip": 0,
            "destination_port": 0
        }
        
        # Check for network connection events
        if event.get("event_id") == 3 or event.get("event_type") == "network_connection":
            features["has_network_activity"] = 1
            
            # Connection direction
            initiated = event.get("initiated") or event.get("connection_initiated")
            if initiated:
                features["is_outbound_connection"] = int(str(initiated).lower() == "true")
            
            # Destination analysis
            dest_ip = event.get("destinationip") or event.get("destination_ip")
            dest_port = event.get("destinationport") or event.get("destination_port")
            
            if dest_port:
                try:
                    port_num = int(dest_port)
                    features["destination_port"] = port_num
                    features["is_suspicious_port"] = int(port_num in self.SUSPICIOUS_PORTS)
                except:
                    pass
            
            if dest_ip:
                try:
                    ip = ipaddress.ip_address(dest_ip)
                    features["is_private_ip"] = int(ip.is_private)
                except:
                    pass
        
        return features
    
    def _extract_user_features(self, event: Dict) -> Dict:
        """Extract user/authentication features"""
        features = {}
        
        # User information
        user = event.get("target_user") or event.get("user_name") or event.get("user", "")
        if user:
            features.update({
                "is_system_user": int(user.lower() in ["system", "local service", "network service"]),
                "is_admin_user": int("admin" in user.lower()),
                "user_name_length": len(user),
                "user_hash": self._hash_string(user.lower()) % 1000
            })
        else:
            features.update({
                "is_system_user": 0, "is_admin_user": 0,
                "user_name_length": 0, "user_hash": 0
            })
        
        # Logon type analysis (for logon events)
        logon_type = event.get("logon_type")
        if logon_type:
            try:
                logon_type_num = int(logon_type)
                features.update({
                    "logon_type": logon_type_num,
                    "is_network_logon": int(logon_type_num == 3),
                    "is_interactive_logon": int(logon_type_num == 2),
                    "is_service_logon": int(logon_type_num == 5)
                })
            except:
                features.update({
                    "logon_type": 0, "is_network_logon": 0,
                    "is_interactive_logon": 0, "is_service_logon": 0
                })
        else:
            features.update({
                "logon_type": 0, "is_network_logon": 0,
                "is_interactive_logon": 0, "is_service_logon": 0
            })
        
        return features
    
    def _extract_file_features(self, event: Dict) -> Dict:
        """Extract file-related features"""
        features = {
            "has_file_activity": 0,
            "is_executable_file": 0,
            "is_suspicious_location": 0,
            "file_name_entropy": 0
        }
        
        # File path analysis
        file_path = (event.get("targetfilename") or 
                    event.get("file_name") or 
                    event.get("filename", ""))
        
        if file_path:
            features["has_file_activity"] = 1
            
            # File extension check
            file_ext = "." + file_path.split(".")[-1].lower() if "." in file_path else ""
            features["is_executable_file"] = int(file_ext in self.SUSPICIOUS_EXTENSIONS)
            
            # Location analysis
            suspicious_paths = ["\\temp\\", "\\appdata\\", "\\programdata\\", "\\public\\"]
            features["is_suspicious_location"] = int(any(path in file_path.lower() for path in suspicious_paths))
            
            # File name entropy
            filename = file_path.split("\\")[-1]
            features["file_name_entropy"] = self._calculate_entropy(filename)
        
        return features
    
    def _extract_registry_features(self, event: Dict) -> Dict:
        """Extract registry-related features"""
        features = {
            "has_registry_activity": 0,
            "is_persistence_key": 0,
            "is_security_key": 0
        }
        
        # Registry key analysis
        reg_key = event.get("targetobject") or event.get("registry_key", "")
        
        if reg_key:
            features["has_registry_activity"] = 1
            
            reg_key_lower = reg_key.lower()
            
            # Persistence indicators
            persistence_keys = [
                "currentversion\\run", "currentversion\\runonce",
                "services\\", "winlogon\\", "policies\\explorer\\run"
            ]
            features["is_persistence_key"] = int(any(key in reg_key_lower for key in persistence_keys))
            
            # Security-related keys
            security_keys = [
                "security\\", "sam\\", "system\\", "software\\policies\\"
            ]
            features["is_security_key"] = int(any(key in reg_key_lower for key in security_keys))
        
        return features
    
    def _extract_behavioral_features(self, event: Dict) -> Dict:
        """Extract behavioral analysis features"""
        features = {}
        
        # LSASS access detection
        features["lsass_access"] = int(event.get("lsass_access", False))
        
        # Persistence indicators
        features["persistence_indicator"] = int(event.get("persistence_indicator", False))
        
        # Suspicious location
        features["suspicious_location"] = int(event.get("suspicious_location", False))
        
        # Risk level encoding
        risk_level = event.get("risk_level", "low")
        risk_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        features["risk_level"] = risk_map.get(risk_level, 1)
        
        return features
    
    def _extract_risk_indicators(self, event: Dict) -> Dict:
        """Extract high-level risk indicators"""
        features = {}
        
        # Event-specific risk scoring
        event_id = event.get("event_id", 0)
        
        # High-risk event IDs
        high_risk_events = {4625, 4648, 4697, 1102, 10}  # Failed logon, explicit creds, service install, log clear, process access
        medium_risk_events = {4624, 4720, 4722}  # Successful logon, account created, account enabled
        
        if event_id in high_risk_events:
            features["event_risk_score"] = 3
        elif event_id in medium_risk_events:
            features["event_risk_score"] = 2
        else:
            features["event_risk_score"] = 1
        
        # Aggregate risk indicators
        risk_indicators = [
            event.get("lsass_access", False),
            event.get("persistence_indicator", False),
            event.get("suspicious_location", False),
            event.get("potential_dga", False)
        ]
        
        features["total_risk_indicators"] = sum(int(indicator) for indicator in risk_indicators)
        
        return features
    
    def _is_suspicious_process_name(self, process_name: str) -> bool:
        """Check if process name is suspicious"""
        suspicious_patterns = [
            r"^[a-f0-9]{8,}\.exe$",  # Hexadecimal names
            r".*\d{4,}\.exe$",       # Names with many digits
            r"^(cmd|powershell|wscript|cscript)\.exe$"  # Script engines
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, process_name.lower()):
                return True
        
        return False
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _hash_string(self, text: str) -> int:
        """Create hash of string for categorical encoding"""
        return int(hashlib.md5(text.encode()).hexdigest(), 16)
    
    def _flatten_features(self, features: Dict) -> Dict:
        """Flatten nested feature dictionary"""
        flattened = {}
        
        for key, value in features.items():
            if isinstance(value, dict):
                for subkey, subvalue in value.items():
                    flattened[f"{key}_{subkey}"] = subvalue
            else:
                flattened[key] = value
        
        return flattened
    
    def _create_feature_vector(self, features: Dict) -> np.ndarray:
        """Create numerical feature vector for ML models"""
        # Ensure consistent feature ordering
        feature_names = sorted(features.keys())
        
        # Convert to numerical values
        vector = []
        for name in feature_names:
            value = features[name]
            
            # Convert to float, handling various data types
            if isinstance(value, (int, float)):
                vector.append(float(value))
            elif isinstance(value, bool):
                vector.append(float(value))
            elif isinstance(value, str):
                vector.append(float(self._hash_string(value) % 1000))
            else:
                vector.append(0.0)
        
        return np.array(vector, dtype=np.float32)
    
    def get_feature_names(self) -> List[str]:
        """Get list of all possible feature names"""
        # This would be populated during training/initialization
        # For now, return a basic set
        return [
            "event_id", "log_type", 
            "temporal_hour_of_day", "temporal_day_of_week", "temporal_is_weekend",
            "temporal_is_business_hours", "temporal_is_night_time",
            "process_is_common_process", "process_name_length", "process_has_suspicious_name",
            "process_cmdline_length", "process_has_powershell", "process_has_encoded_command",
            "network_has_network_activity", "network_is_outbound_connection", "network_is_suspicious_port",
            "user_is_system_user", "user_is_admin_user", "user_logon_type",
            "file_has_file_activity", "file_is_executable_file", "file_is_suspicious_location",
            "registry_has_registry_activity", "registry_is_persistence_key",
            "behavioral_lsass_access", "behavioral_persistence_indicator", "behavioral_risk_level",
            "risk_event_risk_score", "risk_total_risk_indicators"
        ]
