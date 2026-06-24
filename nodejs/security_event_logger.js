/**
 * OWASP Security Event Logger for Node.js
 * A library for logging security events according to the OWASP Logging Vocabulary
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

/**
 * Resolve the bundled security_events.yaml.
 *
 * Prefers the repo-root canonical file when running from a source checkout
 * (single source of truth during development); falls back to the copy shipped
 * inside the published package. Reaching outside the package dir (the prior
 * `../security_events.yaml`-only behavior) meant `npm publish` shipped without
 * the vocabulary — the bundled copy plus the "files" entry in package.json
 * fixes that.
 */
function defaultEventsFile() {
  const candidates = [
    // repo-root canonical: <repo>/security_events.yaml (dev checkout)
    path.join(__dirname, '..', 'security_events.yaml'),
    // packaged copy: <node_modules>/security_event_logger/security_events.yaml
    path.join(__dirname, 'security_events.yaml'),
  ];
  return candidates.find(p => fs.existsSync(p)) || candidates[candidates.length - 1];
}

class SecurityEventLogger {
  /**
   * Initialize the security event logger
   * @param {string} appid - Application identifier
   * @param {string} eventsFile - Path to security_events.yaml file (optional)
   */
  constructor(appid, eventsFile = null) {
    this.appid = appid;
    
    // Load events definition
    if (!eventsFile) {
      eventsFile = defaultEventsFile();
    }
    
    const eventsData = fs.readFileSync(eventsFile, 'utf8');
    const parsed = yaml.load(eventsData);
    if (!parsed || typeof parsed !== 'object' || !parsed.events) {
      throw new Error(`Invalid events definitions file (missing 'events'): ${eventsFile}`);
    }

    this.eventsDef = parsed.events;
  }
  
  /**
   * Log a security event
   * @param {string} eventType - Type of event (e.g., 'authn_login_success')
   * @param {Array} params - Array of parameters for the event
   * @param {Object} options - Optional fields
   * @returns {Object} The log event object
   */
  logEvent(eventType, params = [], options = {}) {
    if (!this.eventsDef[eventType]) {
      throw new Error(`Unknown event type: ${eventType}`);
    }
    
    const eventDef = this.eventsDef[eventType];
    
    // Build event string
    let eventStr = eventType;
    if (params && params.length > 0) {
      eventStr += ':' + params.join(',');
    }
    
    // Build log entry
    const logEntry = {
      datetime: new Date().toISOString(),
      appid: this.appid,
      event: eventStr,
      level: eventDef.level,
      description: options.description || eventDef.description
    };
    
    // Add optional fields
    const optionalFields = [
      'useragent', 'source_ip', 'host_ip', 'hostname',
      'protocol', 'port', 'request_uri', 'request_method',
      'region', 'geo'
    ];
    
    optionalFields.forEach(field => {
      if (options[field]) {
        logEntry[field] = options[field];
      }
    });
    
    // Add any additional custom fields
    Object.keys(options).forEach(key => {
      if (!optionalFields.includes(key) && key !== 'description') {
        logEntry[key] = options[key];
      }
    });
    
    return logEntry;
  }
  
  /**
   * Get information about an event type
   * @param {string} eventType - Type of event
   * @returns {Object} Event information
   */
  getEventInfo(eventType) {
    if (!this.eventsDef[eventType]) {
      throw new Error(`Unknown event type: ${eventType}`);
    }
    
    return this.eventsDef[eventType];
  }
  
  /**
   * List available event types
   * @param {string} category - Optional category filter
   * @returns {Array} List of event type names
   */
  listEvents(category = null) {
    if (category) {
      return Object.keys(this.eventsDef).filter(
        event => this.eventsDef[event].category === category
      );
    }
    return Object.keys(this.eventsDef);
  }
}

module.exports = SecurityEventLogger;
