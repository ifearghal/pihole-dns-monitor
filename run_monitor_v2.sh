#!/bin/bash
# PiHole Monitor Cron Script v2
# Runs every 30 minutes to check for DNS anomalies
# 
# Production-ready features:
# - Proper error handling and logging
# - Environment validation
# - Exit codes for monitoring
# - Log rotation awareness

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-/etc/pihole-monitor/monitor.conf}"
LOG_FILE="${LOG_FILE:-/var/log/pihole-monitor/monitor.log}"
PYTHON="${PYTHON:-/usr/bin/python3}"

# Ensure log directory exists
LOG_DIR="$(dirname "$LOG_FILE")"
mkdir -p "$LOG_DIR"

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Error handler
error() {
    log "ERROR: $*"
    exit 1
}

# Validate environment
validate_environment() {
    # Check Python exists
    if [ ! -x "$PYTHON" ]; then
        error "Python not found at $PYTHON"
    fi
    
    # Check monitor script exists
    if [ ! -f "$SCRIPT_DIR/src/monitor-v2.py" ]; then
        error "Monitor script not found: $SCRIPT_DIR/src/monitor-v2.py"
    fi
    
    # Check config file exists
    if [ ! -f "$CONFIG_FILE" ]; then
        error "Config file not found: $CONFIG_FILE"
    fi
    
    # Check log file is writable
    if ! touch "$LOG_FILE" 2>/dev/null; then
        error "Cannot write to log file: $LOG_FILE"
    fi
}

# Main execution
main() {
    log "===== Starting PiHole monitor run ====="
    
    # Validate environment
    if ! validate_environment; then
        log "Environment validation failed"
        exit 1
    fi
    
    # Run the monitor
    log "Running monitor with config: $CONFIG_FILE"
    
    if "$PYTHON" "$SCRIPT_DIR/src/monitor-v2.py" --config "$CONFIG_FILE" 2>&1 | tee -a "$LOG_FILE"; then
        log "Monitor run completed successfully"
        exit 0
    else
        EXIT_CODE=$?
        log "Monitor run failed with exit code $EXIT_CODE"
        exit $EXIT_CODE
    fi
}

# Execute main function
main "$@"
