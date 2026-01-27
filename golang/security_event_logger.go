package securityeventlogger

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// EventDefinition represents a security event definition
type EventDefinition struct {
	Category    string   `yaml:"category"`
	Prefix      string   `yaml:"prefix"`
	Level       string   `yaml:"level"`
	Description string   `yaml:"description"`
	Parameters  []string `yaml:"parameters"`
}

// EventsData represents the structure of the events YAML file
type EventsData struct {
	Version string                     `yaml:"version"`
	Events  map[string]EventDefinition `yaml:"events"`
}

// LogEntry represents a security log entry
type LogEntry struct {
	DateTime      string            `json:"datetime"`
	AppID         string            `json:"appid"`
	Event         string            `json:"event"`
	Level         string            `json:"level"`
	Description   string            `json:"description"`
	UserAgent     string            `json:"useragent,omitempty"`
	SourceIP      string            `json:"source_ip,omitempty"`
	HostIP        string            `json:"host_ip,omitempty"`
	Hostname      string            `json:"hostname,omitempty"`
	Protocol      string            `json:"protocol,omitempty"`
	Port          string            `json:"port,omitempty"`
	RequestURI    string            `json:"request_uri,omitempty"`
	RequestMethod string            `json:"request_method,omitempty"`
	Region        string            `json:"region,omitempty"`
	Geo           string            `json:"geo,omitempty"`
	Custom        map[string]string `json:"-"`
}

// SecurityEventLogger is the main logger struct
type SecurityEventLogger struct {
	appID     string
	eventsDef map[string]EventDefinition
}

// NewSecurityEventLogger creates a new security event logger
func NewSecurityEventLogger(appID string, eventsFile string) (*SecurityEventLogger, error) {
	if eventsFile == "" {
		// Get the path relative to this file
		_, filename, _, _ := runtime.Caller(0)
		eventsFile = filepath.Join(filepath.Dir(filepath.Dir(filename)), "security_events.yaml")
	}

	data, err := ioutil.ReadFile(eventsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read events file: %w", err)
	}

	var eventsData EventsData
	if err := yaml.Unmarshal(data, &eventsData); err != nil {
		return nil, fmt.Errorf("failed to parse events file: %w", err)
	}

	return &SecurityEventLogger{
		appID:     appID,
		eventsDef: eventsData.Events,
	}, nil
}

// LogEvent logs a security event
func (l *SecurityEventLogger) LogEvent(eventType string, params []string, options map[string]string) (*LogEntry, error) {
	eventDef, exists := l.eventsDef[eventType]
	if !exists {
		return nil, fmt.Errorf("unknown event type: %s", eventType)
	}

	// Build event string
	eventStr := eventType
	if len(params) > 0 {
		eventStr += ":" + strings.Join(params, ",")
	}

	// Get description
	description := eventDef.Description
	if desc, ok := options["description"]; ok {
		description = desc
	}

	// Build log entry
	entry := &LogEntry{
		DateTime:    time.Now().UTC().Format(time.RFC3339),
		AppID:       l.appID,
		Event:       eventStr,
		Level:       eventDef.Level,
		Description: description,
		Custom:      make(map[string]string),
	}

	// Add optional fields
	if val, ok := options["useragent"]; ok {
		entry.UserAgent = val
	}
	if val, ok := options["source_ip"]; ok {
		entry.SourceIP = val
	}
	if val, ok := options["host_ip"]; ok {
		entry.HostIP = val
	}
	if val, ok := options["hostname"]; ok {
		entry.Hostname = val
	}
	if val, ok := options["protocol"]; ok {
		entry.Protocol = val
	}
	if val, ok := options["port"]; ok {
		entry.Port = val
	}
	if val, ok := options["request_uri"]; ok {
		entry.RequestURI = val
	}
	if val, ok := options["request_method"]; ok {
		entry.RequestMethod = val
	}
	if val, ok := options["region"]; ok {
		entry.Region = val
	}
	if val, ok := options["geo"]; ok {
		entry.Geo = val
	}

	// Store custom fields
	knownFields := map[string]bool{
		"description": true, "useragent": true, "source_ip": true,
		"host_ip": true, "hostname": true, "protocol": true,
		"port": true, "request_uri": true, "request_method": true,
		"region": true, "geo": true,
	}
	for key, val := range options {
		if !knownFields[key] {
			entry.Custom[key] = val
		}
	}

	return entry, nil
}

// GetEventInfo returns information about an event type
func (l *SecurityEventLogger) GetEventInfo(eventType string) (*EventDefinition, error) {
	eventDef, exists := l.eventsDef[eventType]
	if !exists {
		return nil, fmt.Errorf("unknown event type: %s", eventType)
	}
	return &eventDef, nil
}

// ListEvents returns a list of available event types
func (l *SecurityEventLogger) ListEvents(category string) []string {
	var events []string
	for eventType, eventDef := range l.eventsDef {
		if category == "" || eventDef.Category == category {
			events = append(events, eventType)
		}
	}
	return events
}

// MarshalJSON implements custom JSON marshaling for LogEntry
func (e *LogEntry) MarshalJSON() ([]byte, error) {
	type Alias LogEntry
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(e),
	}

	// Convert to map to include custom fields
	m := make(map[string]interface{})
	data, _ := json.Marshal(aux)
	json.Unmarshal(data, &m)

	// Add custom fields
	for k, v := range e.Custom {
		m[k] = v
	}

	return json.Marshal(m)
}
