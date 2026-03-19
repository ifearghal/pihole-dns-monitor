#!/bin/bash
# DNS Alert File Watcher
# Monitors PiHole DNS anomaly alerts and spawns security analysis agent
#
# Requires: OpenClaw (https://openclaw.ai) or compatible AI agent framework
# Author: Part of the PiHole DNS Monitor project
# License: MIT

set -euo pipefail

# Configuration - customize these for your environment
ALERT_FILE="${ALERT_FILE:-/path/to/shared/dns-anomaly-alerts.md}"
LOG_FILE="${LOG_FILE:-$HOME/logs/dns-alert-watcher.log}"
OPENCLAW_BIN="${OPENCLAW_BIN:-openclaw}"
SPAWN_COOLDOWN=300  # 5 minutes cooldown between agent spawns

# Agent configuration
AGENT_ID="${AGENT_ID:-robin-security}"  # Your security analysis agent ID
AGENT_TASK="DNS anomaly alert detected. Review the latest entries in $ALERT_FILE and investigate the flagged devices. Determine if this is legitimate traffic or a security concern. Document findings."

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Track last spawn time to prevent spam
LAST_SPAWN_FILE="/tmp/dns-watcher-last-spawn"

# Function to spawn security agent
spawn_security_agent() {
    local now
    now=$(date +%s)
    
    # Check cooldown
    if [ -f "$LAST_SPAWN_FILE" ]; then
        local last_spawn
        last_spawn=$(cat "$LAST_SPAWN_FILE")
        local elapsed=$((now - last_spawn))
        
        if [ "$elapsed" -lt "$SPAWN_COOLDOWN" ]; then
            log "Spawn cooldown active (${elapsed}s elapsed, need ${SPAWN_COOLDOWN}s). Skipping."
            return
        fi
    fi
    
    log "DNS anomaly alert detected! Spawning security agent for investigation..."
    
    # Spawn agent via OpenClaw CLI
    # Adjust this command for your agent framework
    if "$OPENCLAW_BIN" agent spawn \
        --agent-id "$AGENT_ID" \
        --task "$AGENT_TASK" \
        --label "dns-alert-$(date +%Y%m%d-%H%M%S)" \
        --runtime subagent \
        --mode run; then
        
        log "✅ Security agent spawned successfully"
        echo "$now" > "$LAST_SPAWN_FILE"
    else
        log "❌ Failed to spawn agent (exit code: $?)"
    fi
}

# Check prerequisites
if ! command -v "$OPENCLAW_BIN" &> /dev/null; then
    log "ERROR: OpenClaw binary not found: $OPENCLAW_BIN"
    log "Install from: https://openclaw.ai"
    exit 1
fi

if [ ! -f "$ALERT_FILE" ]; then
    log "WARNING: Alert file not found at $ALERT_FILE (will watch for creation)"
fi

# Check if fswatch is installed (macOS/Linux file watcher)
if ! command -v fswatch &> /dev/null; then
    log "ERROR: fswatch not found."
    log "Install: macOS: brew install fswatch | Linux: apt install fswatch / yum install fswatch"
    exit 1
fi

log "DNS Alert Watcher starting..."
log "Monitoring: $ALERT_FILE"
log "Using agent framework: $OPENCLAW_BIN"
log "Agent ID: $AGENT_ID"
log "Spawn cooldown: ${SPAWN_COOLDOWN}s"
log "Watcher active. Waiting for file changes..."

# Watch the file for changes
# -1 = exit after first event (will be restarted by launchd/systemd)
# -l 1 = latency of 1 second (debounce rapid writes)
fswatch -0 -l 1 "$ALERT_FILE" | while read -r -d "" event; do
    log "File change detected: $event"
    spawn_security_agent
done
