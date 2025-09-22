#!/usr/bin/env python3
"""
Sigma Rules Engine
Implementation of Sigma rule matching for Windows events
"""

import logging
import yaml
import re
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

@dataclass
class SigmaRule:
    """Sigma rule representation"""
    id: str
    title: str
    description: str
    level: str
    logsource: Dict
    detection: Dict
    falsepositives: List[str] = None
    references: List[str] = None
    tags: List[str] = None

class SigmaEngine:
    """
    Sigma rules engine for Windows event matching
    
    Implements core Sigma rule logic for detecting known attack patterns
    in Windows security events and Sysmon logs
    """
    
    def __init__(self, rules_path: str = "src/vpew_ai/rules/rules"):
        """
        Initialize Sigma engine
        
        Args:
            rules_path: Path to directory containing Sigma rule files
        """
        self.rules_path = Path(rules_path)
        self.rules: List[SigmaRule] = []
        self.event_buffer = {}  # For time-based correlation
        self.match_cache = {}   # Cache for performance
        
        logger.info(f"Sigma engine initialized with rules path: {rules_path}")
    
    def load_rules(self) -> int:
        """
        Load Sigma rules from YAML files
        
        Returns:
            Number of rules loaded successfully
        """
        loaded_count = 0
        
        try:
            if not self.rules_path.exists():
                logger.warning(f"Rules path does not exist: {self.rules_path}")
                return 0
            
            # Load all .yml files in rules directory
            for rule_file in self.rules_path.glob("*.yml"):
                try:
                    rule = self._load_rule_file(rule_file)
                    if rule:
                        self.rules.append(rule)
                        loaded_count += 1
                        logger.debug(f"Loaded rule: {rule.title}")
                        
                except Exception as e:
                    logger.error(f"Error loading rule {rule_file}: {e}")
            
            logger.info(f"Loaded {loaded_count} Sigma rules")
            return loaded_count
            
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            return 0
    
    def _load_rule_file(self, rule_file: Path) -> Optional[SigmaRule]:
        """
        Load a single Sigma rule file
        
        Args:
            rule_file: Path to rule YAML file
            
        Returns:
            SigmaRule object or None if loading failed
        """
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                rule_data = yaml.safe_load(f)
            
            # Validate required fields
            required_fields = ['title', 'description', 'logsource', 'detection']
            for field in required_fields:
                if field not in rule_data:
                    logger.error(f"Missing required field '{field}' in {rule_file}")
                    return None
            
            # Create SigmaRule object
            rule = SigmaRule(
                id=rule_data.get('id', str(rule_file.stem)),
                title=rule_data['title'],
                description=rule_data['description'],
                level=rule_data.get('level', 'medium'),
                logsource=rule_data['logsource'],
                detection=rule_data['detection'],
                falsepositives=rule_data.get('falsepositives', []),
                references=rule_data.get('references', []),
                tags=rule_data.get('tags', [])
            )
            
            return rule
            
        except Exception as e:
            logger.error(f"Error parsing rule file {rule_file}: {e}")
            return None
    
    def match(self, event: Dict) -> List[Dict]:
        """
        Match event against all loaded Sigma rules
        
        Args:
            event: Normalized event dictionary
            
        Returns:
            List of matching rule dictionaries
        """
        matches = []
        
        for rule in self.rules:
            try:
                if self._match_rule(event, rule):
                    match = {
                        'id': rule.id,
                        'title': rule.title,
                        'description': rule.description,
                        'level': rule.level,
                        'tags': rule.tags or [],
                        'matched_event': event,
                        'timestamp': datetime.now().isoformat()
                    }
                    matches.append(match)
                    logger.info(f"Rule matched: {rule.title}")
                    
            except Exception as e:
                logger.error(f"Error matching rule {rule.title}: {e}")
        
        return matches
    
    def _match_rule(self, event: Dict, rule: SigmaRule) -> bool:
        """
        Check if event matches a specific Sigma rule
        
        Args:
            event: Event to check
            rule: Sigma rule to match against
            
        Returns:
            True if event matches rule, False otherwise
        """
        try:
            # Check logsource compatibility
            if not self._match_logsource(event, rule.logsource):
                return False
            
            # Evaluate detection logic
            return self._evaluate_detection(event, rule.detection)
            
        except Exception as e:
            logger.debug(f"Error matching rule {rule.title}: {e}")
            return False
    
    def _match_logsource(self, event: Dict, logsource: Dict) -> bool:
        """
        Check if event matches rule logsource criteria
        
        Args:
            event: Event to check
            logsource: Logsource specification from rule
            
        Returns:
            True if logsource matches, False otherwise
        """
        # Check product (e.g., "windows")
        product = logsource.get('product')
        if product and product.lower() != 'windows':
            return False
        
        # Check category (e.g., "process_creation", "network_connection")
        category = logsource.get('category')
        if category:
            event_category = self._get_event_category(event)
            if event_category != category:
                return False
        
        # Check service (e.g., "security", "sysmon")
        service = logsource.get('service')
        if service:
            event_service = event.get('log_type', '').lower()
            if service.lower() != event_service:
                return False
        
        return True
    
    def _get_event_category(self, event: Dict) -> str:
        """
        Determine event category from event data
        
        Args:
            event: Event dictionary
            
        Returns:
            Event category string
        """
        event_id = event.get('event_id', 0)
        log_type = event.get('log_type', '').lower()
        
        # Sysmon event categories
        if log_type == 'sysmon':
            sysmon_categories = {
                1: 'process_creation',
                3: 'network_connection',
                10: 'process_access',
                11: 'file_event',
                12: 'registry_event',
                13: 'registry_event',
                22: 'dns_query'
            }
            return sysmon_categories.get(event_id, 'unknown')
        
        # Windows Security event categories
        elif log_type == 'security':
            security_categories = {
                4624: 'authentication',
                4625: 'authentication',
                4697: 'service_installation',
                1102: 'log_clearing'
            }
            return security_categories.get(event_id, 'security')
        
        return 'unknown'
    
    def _evaluate_detection(self, event: Dict, detection: Dict) -> bool:
        """
        Evaluate detection logic against event
        
        Args:
            event: Event to evaluate
            detection: Detection specification from rule
            
        Returns:
            True if detection conditions are met, False otherwise
        """
        try:
            # Get the condition
            condition = detection.get('condition')
            if not condition:
                logger.warning("No condition specified in detection")
                return False
            
            # Evaluate each selection/filter in detection
            context = {}
            for key, value in detection.items():
                if key != 'condition':
                    context[key] = self._evaluate_selection(event, value)
            
            # Evaluate the condition
            return self._evaluate_condition(condition, context)
            
        except Exception as e:
            logger.debug(f"Error evaluating detection: {e}")
            return False
    
    def _evaluate_selection(self, event: Dict, selection: Dict) -> bool:
        """
        Evaluate a selection block against event
        
        Args:
            event: Event to check
            selection: Selection criteria
            
        Returns:
            True if selection matches, False otherwise
        """
        try:
            # Handle different selection types
            if isinstance(selection, dict):
                # All conditions in selection must match (AND logic)
                for field, criteria in selection.items():
                    if not self._match_field(event, field, criteria):
                        return False
                return True
            
            elif isinstance(selection, list):
                # Any condition in list can match (OR logic)
                return any(self._evaluate_selection(event, item) for item in selection)
            
            else:
                logger.warning(f"Unexpected selection type: {type(selection)}")
                return False
                
        except Exception as e:
            logger.debug(f"Error evaluating selection: {e}")
            return False
    
    def _match_field(self, event: Dict, field: str, criteria: Union[str, List, Dict]) -> bool:
        """
        Match event field against criteria
        
        Args:
            event: Event dictionary
            field: Field name to check
            criteria: Matching criteria
            
        Returns:
            True if field matches criteria, False otherwise
        """
        try:
            # Get event field value
            event_value = self._get_event_field(event, field)
            if event_value is None:
                return False
            
            # Convert to string for matching
            event_value_str = str(event_value).lower()
            
            # Handle different criteria types
            if isinstance(criteria, str):
                return self._match_string(event_value_str, criteria.lower())
            
            elif isinstance(criteria, list):
                # Match any item in list (OR logic)
                return any(self._match_string(event_value_str, str(item).lower()) for item in criteria)
            
            elif isinstance(criteria, dict):
                # Handle field modifiers (contains, endswith, etc.)
                for modifier, value in criteria.items():
                    if not self._apply_modifier(event_value_str, modifier, value):
                        return False
                return True
            
            else:
                return str(criteria).lower() == event_value_str
                
        except Exception as e:
            logger.debug(f"Error matching field {field}: {e}")
            return False
    
    def _get_event_field(self, event: Dict, field: str) -> Any:
        """
        Get field value from event, handling nested fields
        
        Args:
            event: Event dictionary
            field: Field name (may be nested with dots)
            
        Returns:
            Field value or None if not found
        """
        try:
            # Handle nested fields (e.g., "process.name")
            if '.' in field:
                parts = field.split('.')
                value = event
                for part in parts:
                    if isinstance(value, dict) and part in value:
                        value = value[part]
                    else:
                        return None
                return value
            
            # Direct field access with common field mappings
            field_mappings = {
                'Image': 'image',
                'CommandLine': 'commandline',
                'ProcessId': 'processid',
                'ParentProcessId': 'parentprocessid',
                'TargetFilename': 'targetfilename',
                'DestinationIp': 'destinationip',
                'DestinationPort': 'destinationport',
                'QueryName': 'queryname',
                'TargetObject': 'targetobject'
            }
            
            # Try direct field name first
            if field in event:
                return event[field]
            
            # Try lowercase version
            field_lower = field.lower()
            if field_lower in event:
                return event[field_lower]
            
            # Try mapped field name
            if field in field_mappings:
                mapped_field = field_mappings[field]
                if mapped_field in event:
                    return event[mapped_field]
            
            return None
            
        except Exception as e:
            logger.debug(f"Error getting field {field}: {e}")
            return None
    
    def _match_string(self, event_value: str, criteria: str) -> bool:
        """
        Match string value against criteria
        
        Args:
            event_value: Event field value
            criteria: Matching criteria
            
        Returns:
            True if matches, False otherwise
        """
        try:
            # Exact match
            if criteria == event_value:
                return True
            
            # Wildcard matching
            if '*' in criteria or '?' in criteria:
                # Convert wildcards to regex
                regex_pattern = criteria.replace('*', '.*').replace('?', '.')
                return bool(re.match(regex_pattern, event_value))
            
            # Substring matching
            if criteria in event_value:
                return True
            
            return False
            
        except Exception as e:
            logger.debug(f"Error matching string: {e}")
            return False
    
    def _apply_modifier(self, event_value: str, modifier: str, criteria: Union[str, List]) -> bool:
        """
        Apply field modifier (contains, endswith, etc.)
        
        Args:
            event_value: Event field value
            modifier: Modifier type
            criteria: Matching criteria
            
        Returns:
            True if modifier condition is met, False otherwise
        """
        try:
            if isinstance(criteria, list):
                return any(self._apply_modifier(event_value, modifier, item) for item in criteria)
            
            criteria_str = str(criteria).lower()
            
            if modifier == 'contains':
                return criteria_str in event_value
            elif modifier == 'endswith':
                return event_value.endswith(criteria_str)
            elif modifier == 'startswith':
                return event_value.startswith(criteria_str)
            elif modifier == 'regex':
                return bool(re.search(criteria_str, event_value))
            else:
                logger.warning(f"Unknown modifier: {modifier}")
                return False
                
        except Exception as e:
            logger.debug(f"Error applying modifier {modifier}: {e}")
            return False
    
    def _evaluate_condition(self, condition: str, context: Dict) -> bool:
        """
        Evaluate condition string with context
        
        Args:
            condition: Condition expression
            context: Context with selection results
            
        Returns:
            True if condition is met, False otherwise
        """
        try:
            # Simple condition evaluation
            # In production, would use a proper expression parser
            
            # Handle basic conditions
            if condition in context:
                return context[condition]
            
            # Handle "not" conditions
            if condition.startswith('not '):
                inner_condition = condition[4:]
                return not context.get(inner_condition, False)
            
            # Handle "and" conditions
            if ' and ' in condition:
                parts = condition.split(' and ')
                return all(context.get(part.strip(), False) for part in parts)
            
            # Handle "or" conditions
            if ' or ' in condition:
                parts = condition.split(' or ')
                return any(context.get(part.strip(), False) for part in parts)
            
            # Default to False for unknown conditions
            logger.warning(f"Unknown condition format: {condition}")
            return False
            
        except Exception as e:
            logger.debug(f"Error evaluating condition: {e}")
            return False
    
    def get_rule_stats(self) -> Dict:
        """
        Get statistics about loaded rules
        
        Returns:
            Dictionary with rule statistics
        """
        stats = {
            "total_rules": len(self.rules),
            "rules_by_level": {},
            "rules_by_category": {}
        }
        
        for rule in self.rules:
            # Count by level
            level = rule.level
            stats["rules_by_level"][level] = stats["rules_by_level"].get(level, 0) + 1
            
            # Count by category (based on logsource)
            category = rule.logsource.get('category', 'unknown')
            stats["rules_by_category"][category] = stats["rules_by_category"].get(category, 0) + 1
        
        return stats
