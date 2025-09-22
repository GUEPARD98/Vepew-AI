"""
Advanced Event Filtering System for VPEW-AI
Provides intelligent filtering, deduplication, and event prioritization
"""

import time
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass
from enum import Enum
import re

logger = logging.getLogger(__name__)

class FilterAction(Enum):
    """Filter actions"""
    ALLOW = "allow"
    BLOCK = "block"
    PRIORITIZE = "prioritize"
    DEPRIORITIZE = "deprioritize"

class EventPriority(Enum):
    """Event priority levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class FilterRule:
    """Individual filter rule"""
    name: str
    description: str
    condition: str  # JSONPath or regex expression
    action: FilterAction
    priority: EventPriority = EventPriority.MEDIUM
    enabled: bool = True
    created_at: datetime = None
    hit_count: int = 0
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class FilteredEvent:
    """Event with filtering metadata"""
    original_event: Dict[str, Any]
    filter_applied: Optional[str] = None
    action: FilterAction = FilterAction.ALLOW
    priority: EventPriority = EventPriority.MEDIUM
    filtered_at: datetime = None
    deduplication_key: Optional[str] = None
    
    def __post_init__(self):
        if self.filtered_at is None:
            self.filtered_at = datetime.now()

class EventFilter:
    """Advanced event filtering system"""
    
    def __init__(self):
        self.rules: List[FilterRule] = []
        self.deduplication_cache: Dict[str, datetime] = {}
        self.cache_ttl = 300  # 5 minutes
        self.stats = {
            'total_events': 0,
            'filtered_events': 0,
            'blocked_events': 0,
            'prioritized_events': 0,
            'deduplicated_events': 0
        }
        
        # Initialize default rules
        self._initialize_default_rules()
        
        logger.info("Event filtering system initialized")
    
    def _initialize_default_rules(self):
        """Initialize default filtering rules"""
        default_rules = [
            FilterRule(
                name="block_system_noise",
                description="Block common system noise events",
                condition="event_id in [4624, 4625, 4634] and log_type == 'Security'",
                action=FilterAction.DEPRIORITIZE,
                priority=EventPriority.LOW
            ),
            FilterRule(
                name="prioritize_security_events",
                description="Prioritize security-related events",
                condition="log_type == 'Security' and event_id in [4625, 4648, 4720, 4732]",
                action=FilterAction.PRIORITIZE,
                priority=EventPriority.HIGH
            ),
            FilterRule(
                name="prioritize_admin_activities",
                description="Prioritize administrative activities",
                condition="'administrator' in user_name.lower() or 'admin' in user_name.lower()",
                action=FilterAction.PRIORITIZE,
                priority=EventPriority.HIGH
            ),
            FilterRule(
                name="prioritize_suspicious_processes",
                description="Prioritize suspicious process activities",
                condition="any(susp in process_name.lower() for susp in ['powershell', 'cmd', 'rundll32', 'regsvr32'])",
                action=FilterAction.PRIORITIZE,
                priority=EventPriority.HIGH
            ),
            FilterRule(
                name="prioritize_network_activities",
                description="Prioritize network-related activities",
                condition="remote_ip is not None and remote_ip != ''",
                action=FilterAction.PRIORITIZE,
                priority=EventPriority.MEDIUM
            ),
            FilterRule(
                name="block_duplicate_events",
                description="Block duplicate events within time window",
                condition="deduplication_key in deduplication_cache",
                action=FilterAction.BLOCK,
                priority=EventPriority.LOW
            )
        ]
        
        for rule in default_rules:
            self.add_rule(rule)
        
        logger.info(f"Initialized {len(default_rules)} default filtering rules")
    
    def add_rule(self, rule: FilterRule) -> bool:
        """Add a new filter rule"""
        try:
            self.rules.append(rule)
            logger.info(f"Added filter rule: {rule.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to add filter rule {rule.name}: {e}")
            return False
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a filter rule by name"""
        try:
            self.rules = [rule for rule in self.rules if rule.name != rule_name]
            logger.info(f"Removed filter rule: {rule_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove filter rule {rule_name}: {e}")
            return False
    
    def enable_rule(self, rule_name: str) -> bool:
        """Enable a filter rule"""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = True
                logger.info(f"Enabled filter rule: {rule_name}")
                return True
        return False
    
    def disable_rule(self, rule_name: str) -> bool:
        """Disable a filter rule"""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = False
                logger.info(f"Disabled filter rule: {rule_name}")
                return True
        return False
    
    def filter_events(self, events: List[Dict[str, Any]]) -> List[FilteredEvent]:
        """Filter a list of events"""
        if not events:
            return []
        
        filtered_events = []
        
        for event in events:
            try:
                filtered_event = self._filter_single_event(event)
                if filtered_event:
                    filtered_events.append(filtered_event)
            except Exception as e:
                logger.error(f"Error filtering event: {e}")
                # Allow event through if filtering fails
                filtered_events.append(FilteredEvent(
                    original_event=event,
                    action=FilterAction.ALLOW,
                    priority=EventPriority.MEDIUM
                ))
        
        # Update statistics
        self.stats['total_events'] += len(events)
        self.stats['filtered_events'] += len(filtered_events)
        
        # Clean up deduplication cache
        self._cleanup_deduplication_cache()
        
        return filtered_events
    
    def _filter_single_event(self, event: Dict[str, Any]) -> Optional[FilteredEvent]:
        """Filter a single event"""
        # Generate deduplication key
        dedup_key = self._generate_deduplication_key(event)
        
        # Check for duplicates
        if self._is_duplicate(dedup_key):
            self.stats['deduplicated_events'] += 1
            return None  # Block duplicate event
        
        # Apply filter rules
        filtered_event = FilteredEvent(
            original_event=event,
            action=FilterAction.ALLOW,
            priority=EventPriority.MEDIUM,
            deduplication_key=dedup_key
        )
        
        for rule in self.rules:
            if not rule.enabled:
                continue
                
            if self._evaluate_rule(rule, event, dedup_key):
                rule.hit_count += 1
                filtered_event.filter_applied = rule.name
                filtered_event.action = rule.action
                filtered_event.priority = rule.priority
                
                if rule.action == FilterAction.BLOCK:
                    self.stats['blocked_events'] += 1
                    return None  # Block event
                elif rule.action == FilterAction.PRIORITIZE:
                    self.stats['prioritized_events'] += 1
                elif rule.action == FilterAction.DEPRIORITIZE:
                    # Lower priority if not already high
                    if filtered_event.priority not in [EventPriority.CRITICAL, EventPriority.HIGH]:
                        filtered_event.priority = EventPriority.LOW
                
                # Apply only the first matching rule
                break
        
        # Add to deduplication cache
        self.deduplication_cache[dedup_key] = datetime.now()
        
        return filtered_event
    
    def _evaluate_rule(self, rule: FilterRule, event: Dict[str, Any], dedup_key: str) -> bool:
        """Evaluate if a rule matches the event"""
        try:
            # Simple rule evaluation (can be extended with more complex logic)
            condition = rule.condition.lower()
            
            # Handle deduplication rule
            if "deduplication_key in deduplication_cache" in condition:
                return dedup_key in self.deduplication_cache
            
            # Handle event_id conditions
            if "event_id in" in condition:
                event_ids = self._extract_list_from_condition(condition, "event_id in")
                if event_ids and event.get('event_id') in event_ids:
                    # Check additional conditions
                    if "and log_type ==" in condition:
                        log_type = condition.split("log_type ==")[1].strip().strip("'\"")
                        return event.get('log_type', '').lower() == log_type.lower()
                    return True
            
            # Handle log_type conditions
            if "log_type ==" in condition:
                log_type = condition.split("log_type ==")[1].strip().strip("'\"")
                if event.get('log_type', '').lower() == log_type.lower():
                    # Check additional conditions
                    if "and event_id in" in condition:
                        event_ids = self._extract_list_from_condition(condition, "event_id in")
                        return event.get('event_id') in event_ids
                    return True
            
            # Handle user_name conditions
            if "user_name" in condition:
                user_name = event.get('user_name', '').lower()
                if "'administrator'" in condition and 'administrator' in user_name:
                    return True
                if "'admin'" in condition and 'admin' in user_name:
                    return True
            
            # Handle process_name conditions
            if "process_name" in condition:
                process_name = event.get('process_name', '').lower()
                suspicious_processes = ['powershell', 'cmd', 'rundll32', 'regsvr32']
                if any(susp in process_name for susp in suspicious_processes):
                    return True
            
            # Handle network conditions
            if "remote_ip" in condition:
                remote_ip = event.get('remote_ip', '')
                if "is not none" in condition and remote_ip and remote_ip != '':
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating rule {rule.name}: {e}")
            return False
    
    def _extract_list_from_condition(self, condition: str, prefix: str) -> List[int]:
        """Extract list of integers from condition string"""
        try:
            start = condition.find(prefix) + len(prefix)
            end = condition.find(']', start)
            if start < end:
                list_str = condition[start:end].strip()
                # Remove brackets and parse
                list_str = list_str.strip('[]')
                return [int(x.strip()) for x in list_str.split(',')]
        except:
            pass
        return []
    
    def _generate_deduplication_key(self, event: Dict[str, Any]) -> str:
        """Generate deduplication key for event"""
        # Use key fields to generate hash
        key_fields = [
            event.get('event_id', ''),
            event.get('log_type', ''),
            event.get('process_name', ''),
            event.get('user_name', ''),
            event.get('remote_ip', ''),
            str(event.get('timestamp', ''))[:10]  # Use date only for deduplication
        ]
        
        key_string = '|'.join(str(field) for field in key_fields)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _is_duplicate(self, dedup_key: str) -> bool:
        """Check if event is duplicate"""
        return dedup_key in self.deduplication_cache
    
    def _cleanup_deduplication_cache(self):
        """Clean up old entries from deduplication cache"""
        cutoff_time = datetime.now() - timedelta(seconds=self.cache_ttl)
        keys_to_remove = [
            key for key, timestamp in self.deduplication_cache.items()
            if timestamp < cutoff_time
        ]
        
        for key in keys_to_remove:
            del self.deduplication_cache[key]
    
    def get_filtered_events_by_priority(self, events: List[FilteredEvent]) -> Dict[EventPriority, List[FilteredEvent]]:
        """Group filtered events by priority"""
        grouped = {priority: [] for priority in EventPriority}
        
        for event in events:
            grouped[event.priority].append(event)
        
        return grouped
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get filtering statistics"""
        return {
            'stats': self.stats.copy(),
            'rules_count': len(self.rules),
            'active_rules': len([rule for rule in self.rules if rule.enabled]),
            'deduplication_cache_size': len(self.deduplication_cache),
            'cache_ttl': self.cache_ttl
        }
    
    def get_rule_statistics(self) -> List[Dict[str, Any]]:
        """Get statistics for each rule"""
        return [
            {
                'name': rule.name,
                'description': rule.description,
                'hit_count': rule.hit_count,
                'enabled': rule.enabled,
                'created_at': rule.created_at.isoformat()
            }
            for rule in self.rules
        ]
    
    def reset_statistics(self):
        """Reset all statistics"""
        self.stats = {
            'total_events': 0,
            'filtered_events': 0,
            'blocked_events': 0,
            'prioritized_events': 0,
            'deduplicated_events': 0
        }
        
        for rule in self.rules:
            rule.hit_count = 0
        
        logger.info("Filtering statistics reset")

def get_event_filter() -> EventFilter:
    """Get event filter instance"""
    return EventFilter()
