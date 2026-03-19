#!/bin/bash
# PiHole Monitor Cron Script
# Runs every 30 minutes to check for DNS anomalies

# Set up environment
export PATH="/usr/local/bin:/usr/bin:/bin"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LOG_FILE="$SCRIPT_DIR/logs/monitor.log"

# Create logs directory if it doesn't exist
mkdir -p "$SCRIPT_DIR/logs"

# Log start
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting PiHole monitor run" >> "$LOG_FILE"

# Run the monitor
cd "$SCRIPT_DIR"
/usr/bin/python3 src/monitor.py \
    --log-path test_data/pihole.log \
    --bulletin-path /opt/workspace/bulletins/infrastructure-board.md \
    >> "$LOG_FILE" 2>&1

# Log completion
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Monitor run completed" >> "$LOG_FILE"
echo "---" >> "$LOG_FILE"