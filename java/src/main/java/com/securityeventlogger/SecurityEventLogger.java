package com.securityeventlogger;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * OWASP Security Event Logger for Java
 * A library for logging security events according to the OWASP Logging Vocabulary
 */
public class SecurityEventLogger {
    private final String appId;
    private final Map<String, EventDefinition> eventsDef;
    private final ObjectMapper objectMapper;

    /**
     * Initialize the security event logger
     * @param appId Application identifier
     * @throws IOException if the events file cannot be read
     */
    public SecurityEventLogger(String appId) throws IOException {
        this(appId, null);
    }

    /**
     * Initialize the security event logger
     * @param appId Application identifier
     * @param eventsFile Path to security_events.json file (optional)
     * @throws IOException if the events file cannot be read
     */
    public SecurityEventLogger(String appId, String eventsFile) throws IOException {
        this.appId = appId;
        this.objectMapper = new ObjectMapper();
        this.eventsDef = new HashMap<>();

        // Load events definition
        JsonNode rootNode;
        if (eventsFile == null || eventsFile.isEmpty()) {
            // Load from classpath or default location
            InputStream is = getClass().getClassLoader().getResourceAsStream("security_events.json");
            if (is == null) {
                // Try parent directory
                eventsFile = "../security_events.json";
                rootNode = objectMapper.readTree(Files.newInputStream(Paths.get(eventsFile)));
            } else {
                rootNode = objectMapper.readTree(is);
            }
        } else {
            rootNode = objectMapper.readTree(Files.newInputStream(Paths.get(eventsFile)));
        }

        JsonNode eventsNode = rootNode.get("events");
        Iterator<Map.Entry<String, JsonNode>> fields = eventsNode.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            String eventType = entry.getKey();
            JsonNode eventNode = entry.getValue();

            EventDefinition eventDef = new EventDefinition(
                eventNode.get("category").asText(),
                eventNode.get("prefix").asText(),
                eventNode.get("level").asText(),
                eventNode.get("description").asText()
            );

            JsonNode paramsNode = eventNode.get("parameters");
            if (paramsNode != null && paramsNode.isArray()) {
                for (JsonNode param : paramsNode) {
                    eventDef.addParameter(param.asText());
                }
            }

            eventsDef.put(eventType, eventDef);
        }
    }

    /**
     * Log a security event
     * @param eventType Type of event (e.g., 'authn_login_success')
     * @param params List of parameters for the event
     * @param options Optional fields
     * @return The log event as a Map
     * @throws IllegalArgumentException if the event type is unknown
     */
    public Map<String, Object> logEvent(String eventType, List<String> params, Map<String, String> options) {
        if (!eventsDef.containsKey(eventType)) {
            throw new IllegalArgumentException("Unknown event type: " + eventType);
        }

        EventDefinition eventDef = eventsDef.get(eventType);

        // Build event string
        StringBuilder eventStr = new StringBuilder(eventType);
        if (params != null && !params.isEmpty()) {
            eventStr.append(":").append(String.join(",", params));
        }

        // Build log entry
        Map<String, Object> logEntry = new LinkedHashMap<>();
        logEntry.put("datetime", ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        logEntry.put("appid", appId);
        logEntry.put("event", eventStr.toString());
        logEntry.put("level", eventDef.getLevel());

        String description = (options != null && options.containsKey("description")) 
            ? options.get("description") 
            : eventDef.getDescription();
        logEntry.put("description", description);

        // Add optional fields
        if (options != null) {
            String[] optionalFields = {
                "useragent", "source_ip", "host_ip", "hostname",
                "protocol", "port", "request_uri", "request_method",
                "region", "geo"
            };

            Set<String> knownFields = new HashSet<>(Arrays.asList(optionalFields));
            knownFields.add("description");

            for (Map.Entry<String, String> entry : options.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();

                if (!key.equals("description") && value != null && !value.isEmpty()) {
                    logEntry.put(key, value);
                }
            }
        }

        return logEntry;
    }

    /**
     * Get information about an event type
     * @param eventType Type of event
     * @return Event information
     * @throws IllegalArgumentException if the event type is unknown
     */
    public EventDefinition getEventInfo(String eventType) {
        if (!eventsDef.containsKey(eventType)) {
            throw new IllegalArgumentException("Unknown event type: " + eventType);
        }
        return eventsDef.get(eventType);
    }

    /**
     * List available event types
     * @param category Optional category filter
     * @return List of event type names
     */
    public List<String> listEvents(String category) {
        List<String> events = new ArrayList<>();
        for (Map.Entry<String, EventDefinition> entry : eventsDef.entrySet()) {
            if (category == null || category.isEmpty() || entry.getValue().getCategory().equals(category)) {
                events.add(entry.getKey());
            }
        }
        return events;
    }

    /**
     * EventDefinition represents a security event definition
     */
    public static class EventDefinition {
        private final String category;
        private final String prefix;
        private final String level;
        private final String description;
        private final List<String> parameters;

        public EventDefinition(String category, String prefix, String level, String description) {
            this.category = category;
            this.prefix = prefix;
            this.level = level;
            this.description = description;
            this.parameters = new ArrayList<>();
        }

        public void addParameter(String parameter) {
            this.parameters.add(parameter);
        }

        public String getCategory() { return category; }
        public String getPrefix() { return prefix; }
        public String getLevel() { return level; }
        public String getDescription() { return description; }
        public List<String> getParameters() { return parameters; }
    }
}
