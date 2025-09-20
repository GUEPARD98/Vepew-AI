#!/usr/bin/env python3
"""
Windows Event Log Collector
Collects security events from Windows Event Logs
"""

import logging
import win32evtlog
import win32evtlogutil
import win32con
from typing import Dict, List, Optional
from datetime import datetime
import json

logger = logging.getLogger(__name__)

class EventCollector:
    """
    Collector for Windows Event Logs
    Focuses on security-relevant events for threat detection
    """
    
    # Critical Event IDs for security monitoring
    SECURITY_EVENT_IDS = {
        4624: "Successful Logon",
        4625: "Failed Logon", 
        4697: "Service Installation",
        1102: "Security Log Cleared",
        4648: "Logon with Explicit Credentials",
        4720: "User Account Created",
        4722: "User Account Enabled",
        4724: "Password Reset Attempt",
        4738: "User Account Changed",
        4740: "User Account Locked",
        4767: "User Account Unlocked",
        4776: "Domain Controller Authentication",
        4778: "Session Reconnected",
        4779: "Session Disconnected",
        4634: "Logoff"
    }
    
    def __init__(self):
        """Initialize Event Log collector"""
        self.server = None  # Local machine
        self.log_types = [
            "Security",
            "System", 
            "Application"
        ]
        self.last_record_ids = {}
        self._initialize_bookmarks()
        
        logger.info("Event Log collector initialized")
    
    def _initialize_bookmarks(self) -> None:
        """Initialize bookmarks to track last processed events"""
        for log_type in self.log_types:
            try:
                # Get handle to event log
                handle = win32evtlog.OpenEventLog(self.server, log_type)
                
                # Get total number of records
                total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
                
                # Start from current position (avoid processing historical events on first run)
                self.last_record_ids[log_type] = total_records
                
                win32evtlog.CloseEventLog(handle)
                
            except Exception as e:
                logger.error(f"Failed to initialize bookmark for {log_type}: {e}")
                self.last_record_ids[log_type] = 0
    
    def collect(self) -> List[Dict]:
        """
        Collect new events from Windows Event Logs
        
        Returns:
            List of event dictionaries with normalized fields
        """
        all_events = []
        
        for log_type in self.log_types:
            try:
                events = self._collect_from_log(log_type)
                all_events.extend(events)
                
            except Exception as e:
                logger.error(f"Error collecting from {log_type} log: {e}")
        
        logger.debug(f"Collected {len(all_events)} events total")
        return all_events
    
    def _collect_from_log(self, log_type: str) -> List[Dict]:
        """
        Collect events from specific log type
        
        Args:
            log_type: Type of event log (Security, System, Application)
            
        Returns:
            List of normalized event dictionaries
        """
        events = []
        
        try:
            # Open event log
            handle = win32evtlog.OpenEventLog(self.server, log_type)
            
            # Get current total records
            total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
            last_processed = self.last_record_ids.get(log_type, 0)
            
            if total_records <= last_processed:
                # No new events
                win32evtlog.CloseEventLog(handle)
                return events
            
            # Read new events (newest first)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            while True:
                try:
                    event_records = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not event_records:
                        break
                    
                    for event_record in event_records:
                        # Skip if already processed
                        if event_record.RecordNumber <= last_processed:
                            continue
                        
                        # Convert to normalized format
                        normalized_event = self._normalize_event(event_record, log_type)
                        if normalized_event:
                            events.append(normalized_event)
                    
                except Exception as e:
                    if "No more items available" in str(e):
                        break
                    else:
                        logger.error(f"Error reading events: {e}")
                        break
            
            # Update bookmark
            self.last_record_ids[log_type] = total_records
            
            win32evtlog.CloseEventLog(handle)
            
        except Exception as e:
            logger.error(f"Failed to collect from {log_type}: {e}")
        
        logger.debug(f"Collected {len(events)} events from {log_type}")
        return events
    
    def _normalize_event(self, event_record, log_type: str) -> Optional[Dict]:
        """
        Normalize Windows event record to standard format
        
        Args:
            event_record: Raw Windows event record
            log_type: Source log type
            
        Returns:
            Normalized event dictionary or None if not relevant
        """
        try:
            event_id = event_record.EventID & 0xFFFF  # Remove severity bits
            
            # Filter for security-relevant events
            if log_type == "Security" and event_id not in self.SECURITY_EVENT_IDS:
                return None
            
            # Basic event structure
            normalized = {
                "event_id": event_id,
                "log_type": log_type,
                "record_number": event_record.RecordNumber,
                "time_generated": event_record.TimeGenerated.isoformat(),
                "time_written": event_record.TimeWritten.isoformat(),
                "source_name": event_record.SourceName,
                "computer_name": event_record.ComputerName,
                "event_type": event_record.EventType,
                "event_category": event_record.EventCategory,
                "user_sid": event_record.Sid,
                "raw_data": event_record.Data
            }
            
            # Extract string data
            if event_record.StringInserts:
                normalized["string_inserts"] = list(event_record.StringInserts)
            
            # Add event description if available
            if event_id in self.SECURITY_EVENT_IDS:
                normalized["event_description"] = self.SECURITY_EVENT_IDS[event_id]
            
            # Extract additional fields based on event type
            self._extract_event_specific_fields(normalized, event_record)
            
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing event: {e}")
            return None
    
    def _extract_event_specific_fields(self, normalized: Dict, event_record) -> None:
        """
        Extract event-specific fields for better analysis
        
        Args:
            normalized: Normalized event dictionary to enhance
            event_record: Raw Windows event record
        """
        event_id = normalized["event_id"]
        string_inserts = normalized.get("string_inserts", [])
        
        try:
            # Logon events (4624, 4625)
            if event_id in [4624, 4625] and len(string_inserts) >= 8:
                normalized.update({
                    "target_user": string_inserts[5] if len(string_inserts) > 5 else None,
                    "target_domain": string_inserts[6] if len(string_inserts) > 6 else None,
                    "logon_type": string_inserts[8] if len(string_inserts) > 8 else None,
                    "logon_process": string_inserts[9] if len(string_inserts) > 9 else None,
                    "authentication_package": string_inserts[10] if len(string_inserts) > 10 else None,
                    "workstation_name": string_inserts[11] if len(string_inserts) > 11 else None,
                    "source_ip": string_inserts[18] if len(string_inserts) > 18 else None,
                    "source_port": string_inserts[19] if len(string_inserts) > 19 else None
                })
            
            # Service installation (4697)
            elif event_id == 4697 and len(string_inserts) >= 5:
                normalized.update({
                    "service_name": string_inserts[0] if len(string_inserts) > 0 else None,
                    "service_file_name": string_inserts[1] if len(string_inserts) > 1 else None,
                    "service_type": string_inserts[2] if len(string_inserts) > 2 else None,
                    "service_start_type": string_inserts[3] if len(string_inserts) > 3 else None,
                    "service_account": string_inserts[4] if len(string_inserts) > 4 else None
                })
            
            # Account management events
            elif event_id in [4720, 4722, 4724, 4738] and len(string_inserts) >= 2:
                normalized.update({
                    "target_account": string_inserts[0] if len(string_inserts) > 0 else None,
                    "target_domain": string_inserts[1] if len(string_inserts) > 1 else None,
                    "subject_account": string_inserts[4] if len(string_inserts) > 4 else None,
                    "subject_domain": string_inserts[5] if len(string_inserts) > 5 else None
                })
            
        except Exception as e:
            logger.debug(f"Error extracting specific fields for event {event_id}: {e}")
    
    def stop(self) -> None:
        """Stop the event collector"""
        logger.info("Event collector stopped")
    
    def get_stats(self) -> Dict:
        """
        Get collector statistics
        
        Returns:
            Dictionary with collector statistics
        """
        return {
            "collector_type": "EventLog",
            "monitored_logs": self.log_types,
            "last_record_ids": self.last_record_ids.copy(),
            "monitored_event_ids": list(self.SECURITY_EVENT_IDS.keys())
        }
