# Python Security Event Logger

A Python library for logging security events according to the OWASP Logging Vocabulary.

## Installation

```bash
pip install -e .
```

## Usage

```python
from security_event_logger import SecurityEventLogger
import json

# Initialize the logger
logger = SecurityEventLogger(appid="myapp.auth")

# Log a successful login
event = logger.log_event(
    event_type="authn_login_success",
    params=["joebob1"],
    description="User joebob1 logged in successfully",
    source_ip="192.168.1.100",
    useragent="Mozilla/5.0..."
)

# Print as JSON
print(json.dumps(event, indent=2))

# Log a failed login
event = logger.log_event(
    event_type="authn_login_fail",
    params=["baduser"],
    source_ip="192.168.1.200"
)

# List all available events
all_events = logger.list_events()
print(f"Available events: {len(all_events)}")

# List events by category
auth_events = logger.list_events(category="Authentication")
print(f"Authentication events: {auth_events}")

# Get event information
info = logger.get_event_info("authn_login_success")
print(f"Event level: {info['level']}")
print(f"Event description: {info['description']}")
```

## Event Types

The library supports all OWASP Logging Vocabulary event types including:

- Authentication events (authn_*)
- Authorization events (authz_*)
- Session management (session_*)
- User management (user_*)
- File operations (file_*)
- Input validation (input_*)
- System events (sys_*)
- And more...

See `security_events.yaml` for the complete list of supported events.
