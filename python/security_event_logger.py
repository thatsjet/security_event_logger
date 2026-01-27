"""
OWASP Security Event Logger for Python
A library for logging security events according to the OWASP Logging Vocabulary
"""

import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

import yaml


class SecurityEventLogger:
    """Logger for OWASP security events"""
    
    def __init__(self, appid: str, events_file: Optional[str] = None):
        """
        Initialize the security event logger
        
        Args:
            appid: Application identifier
            events_file: Path to security_events.yaml file (optional)
        """
        self.appid = appid
        
        # Load events definition
        if events_file is None:
            events_file = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), 
                'security_events.yaml'
            )

        with open(events_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict) or not isinstance(data.get('events'), dict):
            raise ValueError(f"Invalid events definition file (expected YAML with top-level 'events' mapping): {events_file}")

        self.events_def = data['events']
    
    def log_event(
        self,
        event_type: str,
        params: List[Any],
        description: Optional[str] = None,
        useragent: Optional[str] = None,
        source_ip: Optional[str] = None,
        host_ip: Optional[str] = None,
        hostname: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[str] = None,
        request_uri: Optional[str] = None,
        request_method: Optional[str] = None,
        region: Optional[str] = None,
        geo: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Log a security event
        
        Args:
            event_type: Type of event (e.g., 'authn_login_success')
            params: List of parameters for the event
            description: Optional custom description
            useragent: User agent string
            source_ip: Source IP address
            host_ip: Host IP address
            hostname: Hostname
            protocol: Protocol used (http, https, etc.)
            port: Port number
            request_uri: Request URI
            request_method: HTTP method
            region: Region/datacenter
            geo: Geographic location
            **kwargs: Additional custom fields
            
        Returns:
            Dictionary containing the log event
        """
        if event_type not in self.events_def:
            raise ValueError(f"Unknown event type: {event_type}")
        
        event_def = self.events_def[event_type]
        
        # Build event string
        event_str = event_type
        if params:
            event_str += ":" + ",".join(str(p) for p in params)
        
        # Build log entry
        log_entry = {
            "datetime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z"),
            "appid": self.appid,
            "event": event_str,
            "level": event_def['level'],
            "description": description or event_def['description']
        }
        
        # Add optional fields
        if useragent:
            log_entry['useragent'] = useragent
        if source_ip:
            log_entry['source_ip'] = source_ip
        if host_ip:
            log_entry['host_ip'] = host_ip
        if hostname:
            log_entry['hostname'] = hostname
        if protocol:
            log_entry['protocol'] = protocol
        if port:
            log_entry['port'] = port
        if request_uri:
            log_entry['request_uri'] = request_uri
        if request_method:
            log_entry['request_method'] = request_method
        if region:
            log_entry['region'] = region
        if geo:
            log_entry['geo'] = geo
        
        # Add any additional custom fields
        log_entry.update(kwargs)
        
        return log_entry
    
    def get_event_info(self, event_type: str) -> Dict[str, Any]:
        """
        Get information about an event type
        
        Args:
            event_type: Type of event
            
        Returns:
            Dictionary with event information
        """
        if event_type not in self.events_def:
            raise ValueError(f"Unknown event type: {event_type}")
        
        return self.events_def[event_type]
    
    def list_events(self, category: Optional[str] = None) -> List[str]:
        """
        List available event types
        
        Args:
            category: Optional category filter
            
        Returns:
            List of event type names
        """
        if category:
            return [
                event for event, info in self.events_def.items()
                if info['category'] == category
            ]
        return list(self.events_def.keys())
