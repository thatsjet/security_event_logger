# Node.js Security Event Logger

A Node.js library for logging security events according to the OWASP Logging Vocabulary.

## Installation

```bash
npm install
```

## Usage

```javascript
const SecurityEventLogger = require('./security_event_logger');

// Initialize the logger
const logger = new SecurityEventLogger('myapp.auth');

// Log a successful login
const event = logger.logEvent(
  'authn_login_success',
  ['joebob1'],
  {
    description: 'User joebob1 logged in successfully',
    source_ip: '192.168.1.100',
    useragent: 'Mozilla/5.0...'
  }
);

// Print as JSON
console.log(JSON.stringify(event, null, 2));

// Log a failed login
const failEvent = logger.logEvent(
  'authn_login_fail',
  ['baduser'],
  {
    source_ip: '192.168.1.200'
  }
);

// List all available events
const allEvents = logger.listEvents();
console.log(`Available events: ${allEvents.length}`);

// List events by category
const authEvents = logger.listEvents('Authentication');
console.log(`Authentication events:`, authEvents);

// Get event information
const info = logger.getEventInfo('authn_login_success');
console.log(`Event level: ${info.level}`);
console.log(`Event description: ${info.description}`);
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

See `security_events.json` for the complete list of supported events.
