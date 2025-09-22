#!/usr/bin/env python3
"""
Sysmon Event Collector
Collects detailed system monitoring events from Sysmon
"""

import logging
import win32evtlog
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class SysmonCollector:
    """
    Collector for Sysmon events
    Provides detailed process, network, and file system monitoring
    """
    
    # Critical Sysmon Event IDs for threat detection
    SYSMON_EVENT_IDS = {
        1: "Process Creation",
        2: "File Creation Time Changed", 
        3: "Network Connection",
        4: "Sysmon Service State Changed",
        5: "Process Terminated",
        6: "Driver Loaded",
        7: "Image Loaded",
        8: "CreateRemoteThread",
        9: "RawAccessRead",
        10: "ProcessAccess",
        11: "FileCreate",
        12: "RegistryEvent (Object create and delete)",
        13: "RegistryEvent (Value Set)",
        14: "RegistryEvent (Key and Value Rename)",
        15: "FileCreateStreamHash",
        17: "PipeEvent (Pipe Created)",
        18: "PipeEvent (Pipe Connected)",
        19: "WmiEvent (WmiEventFilter activity detected)",
        20: "WmiEvent (WmiEventConsumer activity detected)",
        21: "WmiEvent (WmiEventConsumerToFilter activity detected)",
        22: "DNSEvent (DNS query)",
        23: "FileDelete (File Delete archived)",
        24: "ClipboardChange (New content in the clipboard)",
        25: "ProcessTampering (Process image change)",
        26: "FileDeleteDetected (File Delete logged)"
    }
    
    def __init__(self):
        """Initialize Sysmon collector"""
        self.server = None  # Local machine
        self.log_name = "Microsoft-Windows-Sysmon/Operational"
        self.last_record_id = 0
        self._initialize_bookmark()
        
        logger.info("Sysmon collector initialized")
    
    def _initialize_bookmark(self) -> None:
        """Initialize bookmark to track last processed event"""
        try:
            # Open Sysmon event log
            handle = win32evtlog.OpenEventLog(self.server, self.log_name)
            
            # Get total number of records
            total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
            
            # Start from current position
            self.last_record_id = total_records
            
            win32evtlog.CloseEventLog(handle)
            
        except Exception as e:
            logger.error(f"Failed to initialize Sysmon bookmark: {e}")
            self.last_record_id = 0
    
    def collect(self) -> List[Dict]:
        """
        Collect new Sysmon events
        
        Returns:
            List of normalized Sysmon event dictionaries
        """
        events = []
        
        try:
            # Open Sysmon event log
            handle = win32evtlog.OpenEventLog(self.server, self.log_name)
            
            # Get current total records
            total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
            
            if total_records <= self.last_record_id:
                # No new events
                win32evtlog.CloseEventLog(handle)
                return events
            
            # Read new events
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            while True:
                try:
                    event_records = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not event_records:
                        break
                    
                    for event_record in event_records:
                        # Skip if already processed
                        if event_record.RecordNumber <= self.last_record_id:
                            continue
                        
                        # Convert to normalized format
                        normalized_event = self._normalize_sysmon_event(event_record)
                        if normalized_event:
                            events.append(normalized_event)
                
                except Exception as e:
                    if "No more items available" in str(e):
                        break
                    else:
                        logger.error(f"Error reading Sysmon events: {e}")
                        break
            
            # Update bookmark
            self.last_record_id = total_records
            
            win32evtlog.CloseEventLog(handle)
            
        except Exception as e:
            logger.error(f"Failed to collect Sysmon events: {e}")
        
        logger.debug(f"Collected {len(events)} Sysmon events")
        return events
    
    def _normalize_sysmon_event(self, event_record) -> Optional[Dict]:
        """
        Normalize Sysmon event record to standard format
        
        Args:
            event_record: Raw Sysmon event record
            
        Returns:
            Normalized event dictionary or None if parsing fails
        """
        try:
            event_id = event_record.EventID & 0xFFFF
            
            # Basic event structure
            normalized = {
                "event_id": event_id,
                "log_type": "Sysmon",
                "record_number": event_record.RecordNumber,
                "time_generated": event_record.TimeGenerated.isoformat(),
                "computer_name": event_record.ComputerName,
                "source_name": event_record.SourceName,
                "user_sid": event_record.Sid
            }
            
            # Add event description
            if event_id in self.SYSMON_EVENT_IDS:
                normalized["event_description"] = self.SYSMON_EVENT_IDS[event_id]
            
            # Parse XML data for detailed fields
            xml_data = self._extract_xml_data(event_record)
            if xml_data:
                normalized.update(xml_data)
            
            # Extract event-specific fields
            self._extract_sysmon_specific_fields(normalized, event_id)
            
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing Sysmon event: {e}")
            return None
    
    def _extract_xml_data(self, event_record) -> Optional[Dict]:
        """
        Extract structured data from Sysmon XML format
        
        Args:
            event_record: Raw Sysmon event record
            
        Returns:
            Dictionary with extracted XML data
        """
        try:
            # Get the XML string from StringInserts
            if not event_record.StringInserts or len(event_record.StringInserts) == 0:
                return None
            
            xml_string = event_record.StringInserts[0]
            
            # Parse XML
            root = ET.fromstring(xml_string)
            
            # Extract all data elements
            data = {}
            for elem in root.iter():
                if elem.tag.startswith('Data') and elem.attrib.get('Name'):
                    field_name = elem.attrib['Name']
                    field_value = elem.text
                    data[field_name.lower()] = field_value
            
            return data
            
        except Exception as e:
            logger.debug(f"Error parsing XML data: {e}")
            return None
    
    def _extract_sysmon_specific_fields(self, normalized: Dict, event_id: int) -> None:
        """
        Extract event-specific fields for better analysis
        
        Args:
            normalized: Normalized event dictionary to enhance
            event_id: Sysmon event ID
        """
        try:
            # Process Creation (Event ID 1)
            if event_id == 1:
                normalized["event_type"] = "process_creation"
                # Fields already extracted from XML: Image, CommandLine, ProcessId, etc.
            
            # Network Connection (Event ID 3)
            elif event_id == 3:
                normalized["event_type"] = "network_connection"
                # Extract connection direction
                if "initiated" in normalized:
                    normalized["connection_initiated"] = normalized["initiated"] == "true"
            
            # Process Access (Event ID 10) - Critical for credential dumping detection
            elif event_id == 10:
                normalized["event_type"] = "process_access"
                # Check for LSASS access
                if "targetimage" in normalized:
                    target_image = normalized["targetimage"].lower()
                    if "lsass.exe" in target_image:
                        normalized["lsass_access"] = True
                        normalized["risk_level"] = "high"
            
            # Registry Events (Event ID 12, 13, 14)
            elif event_id in [12, 13, 14]:
                normalized["event_type"] = "registry_event"
                # Check for persistence-related registry keys
                if "targetobject" in normalized:
                    target_object = normalized["targetobject"].lower()
                    persistence_keys = [
                        "currentversion\\run",
                        "currentversion\\runonce", 
                        "services\\",
                        "winlogon\\",
                        "policies\\explorer\\run"
                    ]
                    for key in persistence_keys:
                        if key in target_object:
                            normalized["persistence_indicator"] = True
                            normalized["risk_level"] = "medium"
                            break
            
            # File Creation (Event ID 11)
            elif event_id == 11:
                normalized["event_type"] = "file_creation"
                # Check for suspicious file locations
                if "targetfilename" in normalized:
                    filename = normalized["targetfilename"].lower()
                    suspicious_paths = [
                        "\\temp\\",
                        "\\appdata\\roaming\\",
                        "\\programdata\\",
                        "\\public\\"
                    ]
                    for path in suspicious_paths:
                        if path in filename:
                            normalized["suspicious_location"] = True
                            break
            
            # DNS Query (Event ID 22)
            elif event_id == 22:
                normalized["event_type"] = "dns_query"
                # Check for suspicious domains
                if "queryname" in normalized:
                    query_name = normalized["queryname"].lower()
                    # Basic DGA detection (domain generation algorithm)
                    if len(query_name) > 20 and any(char.isdigit() for char in query_name):
                        normalized["potential_dga"] = True
                        normalized["risk_level"] = "medium"
            
        except Exception as e:
            logger.debug(f"Error extracting specific fields for Sysmon event {event_id}: {e}")
    
    def stop(self) -> None:
        """Stop the Sysmon collector"""
        logger.info("Sysmon collector stopped")
    
    def get_stats(self) -> Dict:
        """
        Get collector statistics
        
        Returns:
            Dictionary with collector statistics
        """
        return {
            "collector_type": "Sysmon",
            "log_name": self.log_name,
            "last_record_id": self.last_record_id,
            "monitored_event_ids": list(self.SYSMON_EVENT_IDS.keys())
        }
