# Go Security Event Logger

A Go library for logging security events according to the OWASP Logging Vocabulary.

## Installation

```bash
go get github.com/thatsjet/security_event_logger/golang
```

## Usage

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    
    securityeventlogger "github.com/thatsjet/security_event_logger/golang"
)

func main() {
    // Initialize the logger
    logger, err := securityeventlogger.NewSecurityEventLogger("myapp.auth", "")
    if err != nil {
        log.Fatal(err)
    }
    
    // Log a successful login
    options := map[string]string{
        "description": "User joebob1 logged in successfully",
        "source_ip":   "192.168.1.100",
        "useragent":   "Mozilla/5.0...",
    }
    
    event, err := logger.LogEvent("authn_login_success", []string{"joebob1"}, options)
    if err != nil {
        log.Fatal(err)
    }
    
    // Print as JSON
    jsonData, _ := json.MarshalIndent(event, "", "  ")
    fmt.Println(string(jsonData))
    
    // Log a failed login
    failOptions := map[string]string{
        "source_ip": "192.168.1.200",
    }
    
    failEvent, err := logger.LogEvent("authn_login_fail", []string{"baduser"}, failOptions)
    if err != nil {
        log.Fatal(err)
    }
    
    // List all available events
    allEvents := logger.ListEvents("")
    fmt.Printf("Available events: %d\n", len(allEvents))
    
    // List events by category
    authEvents := logger.ListEvents("Authentication")
    fmt.Printf("Authentication events: %v\n", authEvents)
    
    // Get event information
    info, err := logger.GetEventInfo("authn_login_success")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Event level: %s\n", info.Level)
    fmt.Printf("Event description: %s\n", info.Description)
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

See `security_events.yaml` for the complete list of supported events.

