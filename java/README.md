# Java Security Event Logger

A Java library for logging security events according to the OWASP Logging Vocabulary.

## Installation

```bash
mvn clean install
```

## Usage

```java
package com.example;

import com.securityeventlogger.SecurityEventLogger;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;

public class Example {
    public static void main(String[] args) {
        try {
            // Initialize the logger
            SecurityEventLogger logger = new SecurityEventLogger("myapp.auth");
            
            // Log a successful login
            Map<String, String> options = new HashMap<>();
            options.put("description", "User joebob1 logged in successfully");
            options.put("source_ip", "192.168.1.100");
            options.put("useragent", "Mozilla/5.0...");
            
            List<String> params = Arrays.asList("joebob1");
            Map<String, Object> event = logger.logEvent("authn_login_success", params, options);
            
            // Print as JSON
            ObjectMapper mapper = new ObjectMapper();
            String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(event);
            System.out.println(json);
            
            // Log a failed login
            Map<String, String> failOptions = new HashMap<>();
            failOptions.put("source_ip", "192.168.1.200");
            
            List<String> failParams = Arrays.asList("baduser");
            Map<String, Object> failEvent = logger.logEvent("authn_login_fail", failParams, failOptions);
            
            // List all available events
            List<String> allEvents = logger.listEvents(null);
            System.out.println("Available events: " + allEvents.size());
            
            // List events by category
            List<String> authEvents = logger.listEvents("Authentication");
            System.out.println("Authentication events: " + authEvents);
            
            // Get event information
            SecurityEventLogger.EventDefinition info = logger.getEventInfo("authn_login_success");
            System.out.println("Event level: " + info.getLevel());
            System.out.println("Event description: " + info.getDescription());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
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
