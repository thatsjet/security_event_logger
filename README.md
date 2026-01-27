# Security Event Logger

A collection of libraries that implement event logging according to the OWASP Logging Vocabulary.

## Overview

This project provides a standardized way to log security events across multiple programming languages based on the [OWASP Logging Vocabulary Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Logging_Vocabulary_Cheat_Sheet.md).

The goal is to simplify monitoring and alerting by using a consistent vocabulary for security events across all applications, regardless of the programming language used.

## Features

- **Language-agnostic event definitions** stored in YAML format
- **Multi-language support**: Python, Node.js, Go, and Java
- **Comprehensive event coverage**: Authentication, Authorization, Session Management, File Operations, User Management, and more
- **Standardized log format** following OWASP guidelines
- **Easy integration** into existing applications

## Structure

```
security_event_logger/
├── security_events.yaml    # Core event definitions (language-agnostic)
├── python/                 # Python implementation
├── nodejs/                 # Node.js implementation
├── golang/                 # Go implementation
└── java/                   # Java implementation
```

## Event Definitions

All security events are defined in `security_events.yaml`, which serves as the single source of truth for all language implementations. This ensures consistency across different platforms.

### Event Categories

The library supports the following event categories:

- **Authentication (authn_*)**: Login success/failure, password changes, token management
- **Authorization (authz_*)**: Access control violations, permission changes
- **Session Management (session_*)**: Session creation, renewal, expiration
- **User Management (user_*)**: User creation, updates, deletion
- **File Operations (file_*)**: File uploads, integrity checks
- **Input Validation (input_*)**: Input validation failures
- **Excessive Use (excess_*)**: Rate limiting, resource exhaustion
- **Malicious Behavior (malicious_*)**: Attack detection, CSRF, CORS violations
- **System Events (sys_*)**: Startup, shutdown, crashes, monitoring
- **Sensitive Data (sensitive_*)**: Access to sensitive information

## Log Format

All implementations follow the OWASP standard log format:

```json
{
  "datetime": "2021-01-01T01:01:01+0000",
  "appid": "myapp.auth",
  "event": "authn_login_success:joebob1",
  "level": "INFO",
  "description": "User joebob1 login successfully",
  "useragent": "Mozilla/5.0...",
  "source_ip": "192.168.1.100",
  "host_ip": "10.12.7.9",
  "hostname": "auth.example.com",
  "protocol": "https",
  "port": "443",
  "request_uri": "/api/v2/auth/",
  "request_method": "POST",
  "region": "AWS-US-WEST-2",
  "geo": "USA"
}
```

## Language-Specific Documentation

Each implementation has its own README with installation and usage instructions:

- [Python](python/README.md)
- [Node.js](nodejs/README.md)
- [Go](golang/README.md)
- [Java](java/README.md)

## Quick Start Examples

### Python

```python
from security_event_logger import SecurityEventLogger

logger = SecurityEventLogger(appid="myapp.auth")
event = logger.log_event("authn_login_success", ["joebob1"], source_ip="192.168.1.100")
```

### Node.js

```javascript
const SecurityEventLogger = require('./security_event_logger');

const logger = new SecurityEventLogger('myapp.auth');
const event = logger.logEvent('authn_login_success', ['joebob1'], { source_ip: '192.168.1.100' });
```

### Go

```go
import securityeventlogger "github.com/thatsjet/security_event_logger/golang"

logger, _ := securityeventlogger.NewSecurityEventLogger("myapp.auth", "")
options := map[string]string{"source_ip": "192.168.1.100"}
event, _ := logger.LogEvent("authn_login_success", []string{"joebob1"}, options)
```

### Java

```java
import com.securityeventlogger.SecurityEventLogger;

SecurityEventLogger logger = new SecurityEventLogger("myapp.auth");
Map<String, String> options = new HashMap<>();
options.put("source_ip", "192.168.1.100");
Map<String, Object> event = logger.logEvent("authn_login_success", Arrays.asList("joebob1"), options);
```

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is released under the CC0 1.0 Universal (CC0 1.0) Public Domain Dedication. See [LICENSE](LICENSE) for details.

## References

- [OWASP Logging Vocabulary Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Logging_Vocabulary_Cheat_Sheet.md)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
