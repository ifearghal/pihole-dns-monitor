# DNS Alert Watcher - Event-Driven Security Response

Automatically spawns AI security agents when PiHole DNS anomalies are detected.

## Overview

This component watches the DNS anomaly alert file and triggers automated security investigation when new alerts appear. Instead of waiting hours to notice a DNS issue, your security agent responds within seconds.

## How It Works

```
1. PiHole Monitor detects anomaly
   ↓
2. Writes alert to shared file
   ↓
3. File watcher detects change
   ↓
4. Spawns security AI agent
   ↓
5. Agent investigates and reports findings
```

**Response time:** Typically < 10 seconds from detection to agent spawn

## Requirements

- **fswatch** - File system watcher
  - macOS: `brew install fswatch`
  - Ubuntu/Debian: `apt install fswatch`
  - RHEL/Fedora: `yum install fswatch`
  
- **OpenClaw** (or compatible AI agent framework)
  - Download: https://openclaw.ai
  - Alternative: Adapt script for your agent framework

- **Shared file system** - Alert file accessible to both monitor and watcher
  - NFS, SMB, or local filesystem

## Setup

### 1. Configure the Watcher

Edit `dns-alert-watcher.sh` and set these variables:

```bash
# Where the PiHole monitor writes alerts
ALERT_FILE="/path/to/shared/dns-anomaly-alerts.md"

# Where to log watcher activity
LOG_FILE="$HOME/logs/dns-alert-watcher.log"

# Your AI agent framework binary
OPENCLAW_BIN="openclaw"

# Cooldown between agent spawns (prevents spam)
SPAWN_COOLDOWN=300  # 5 minutes

# Your security analysis agent ID
AGENT_ID="robin-security"  # Or whatever you named your security agent
```

### 2. Run the Watcher

**Option A: Run manually (testing)**
```bash
./dns-alert-watcher.sh
```

**Option B: Run as macOS launch agent (recommended)**
```bash
# Copy launchd plist
cp com.user.dns-alert-watcher.plist ~/Library/LaunchAgents/

# Edit paths in the plist file
nano ~/Library/LaunchAgents/com.user.dns-alert-watcher.plist

# Load and start
launchctl load ~/Library/LaunchAgents/com.user.dns-alert-watcher.plist
launchctl start com.user.dns-alert-watcher
```

**Option C: Run as systemd service (Linux)**
```bash
# Copy service file
sudo cp dns-alert-watcher.service /etc/systemd/system/

# Edit paths in service file
sudo nano /etc/systemd/system/dns-alert-watcher.service

# Enable and start
sudo systemctl enable dns-alert-watcher
sudo systemctl start dns-alert-watcher

# Check status
sudo systemctl status dns-alert-watcher
```

### 3. Test It

```bash
# Trigger a test alert
echo "[$(date)] TEST ALERT - Device 10.0.0.99: 3000 queries" >> /path/to/dns-anomaly-alerts.md

# Check watcher log
tail -f ~/logs/dns-alert-watcher.log

# Expected output:
# [2026-03-18 20:30:15] File change detected: /path/to/dns-anomaly-alerts.md
# [2026-03-18 20:30:15] DNS anomaly alert detected! Spawning security agent...
# [2026-03-18 20:30:17] ✅ Security agent spawned successfully
```

## Configuration

### Spawn Cooldown

Prevents agent spam if multiple alerts fire rapidly:

```bash
SPAWN_COOLDOWN=300  # Only spawn agent once every 5 minutes max
```

**Tuning guidance:**
- **High-traffic network**: 600s (10 min) to avoid spam
- **Home network**: 300s (5 min) is usually fine
- **Critical environment**: 60s (1 min) for faster response

### Agent Task Customization

Edit the `AGENT_TASK` variable to customize what your security agent does:

```bash
AGENT_TASK="DNS anomaly detected. Review alerts at $ALERT_FILE. 
Investigate flagged devices:
1. Check recent query patterns
2. Identify unusual domains
3. Assess threat level (benign/suspicious/malicious)
4. Recommend action (monitor/block/investigate further)
Document findings in security bulletin."
```

## Monitoring

### Check Watcher Status

```bash
# View recent activity
tail -20 ~/logs/dns-alert-watcher.log

# Follow in real-time
tail -f ~/logs/dns-alert-watcher.log

# Check if running (macOS)
ps aux | grep dns-alert-watcher

# Check if running (Linux systemd)
sudo systemctl status dns-alert-watcher
```

### Log Output Examples

**Normal operation:**
```
[2026-03-18 14:00:00] DNS Alert Watcher starting...
[2026-03-18 14:00:00] Monitoring: /mnt/shared/dns-anomaly-alerts.md
[2026-03-18 14:00:00] Watcher active. Waiting for file changes...
```

**Alert detected:**
```
[2026-03-18 15:30:15] File change detected: /mnt/shared/dns-anomaly-alerts.md
[2026-03-18 15:30:15] DNS anomaly alert detected! Spawning security agent...
[2026-03-18 15:30:17] ✅ Security agent spawned successfully
```

**Cooldown active:**
```
[2026-03-18 15:32:00] File change detected: /mnt/shared/dns-anomaly-alerts.md
[2026-03-18 15:32:00] Spawn cooldown active (115s elapsed, need 300s). Skipping.
```

## Troubleshooting

### Watcher Not Starting

**Error:** `fswatch: command not found`
- **Fix:** Install fswatch (see Requirements)

**Error:** `OpenClaw binary not found`
- **Fix:** Set correct path in `OPENCLAW_BIN` or install OpenClaw

**Error:** `Alert file not found`
- **Fix:** Create the directory or update `ALERT_FILE` path

### Agent Not Spawning

**Check agent framework:**
```bash
# Test OpenClaw directly
openclaw agent list

# Verify your security agent exists
openclaw agent list | grep robin-security
```

**Check permissions:**
```bash
# Ensure alert file is readable
ls -l /path/to/dns-anomaly-alerts.md

# Ensure log directory is writable
ls -ld ~/logs/
```

**Check cooldown:**
```bash
# See when last spawn occurred
cat /tmp/dns-watcher-last-spawn
date -r $(cat /tmp/dns-watcher-last-spawn)
```

### File Watcher Not Detecting Changes

**macOS FSEvents issue:**
- NFS/network filesystems may not trigger FSEvents
- **Fix:** Use `--event-flags` or poll mode
- **Alternative:** Run watcher on same machine as monitor

**Linux inotify limits:**
```bash
# Check current limit
cat /proc/sys/fs/inotify/max_user_watches

# Increase if needed
echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## Integration with Other Frameworks

### Not Using OpenClaw?

Adapt the `spawn_security_agent` function for your framework:

**For Python agents:**
```bash
spawn_security_agent() {
    python3 /path/to/your_security_agent.py \
        --task "Investigate DNS alerts" \
        --alert-file "$ALERT_FILE"
}
```

**For webhook/API triggers:**
```bash
spawn_security_agent() {
    curl -X POST https://your-agent-api.com/spawn \
        -H "Content-Type: application/json" \
        -d "{\"agent\":\"security\",\"task\":\"dns_investigation\"}"
}
```

**For email alerts:**
```bash
spawn_security_agent() {
    mail -s "DNS Anomaly Detected" security@example.com < "$ALERT_FILE"
}
```

## Performance

- **File watch overhead:** Negligible (<1% CPU, ~5MB RAM)
- **Spawn time:** Typically 2-5 seconds (framework dependent)
- **Alert latency:** Usually < 10 seconds total

## Security Considerations

- Alert file should be on secure filesystem
- Watcher runs with user privileges (no sudo needed)
- Agent spawning is rate-limited (cooldown)
- All file paths are sanitized

## Example Deployment

**Network Setup:**
```
[PiHole Server]
  └─ Monitor writes alerts every 30min
     └─ NFS share: /exports/shared/dns-alerts.md

[Mac/Linux Workstation]
  └─ NFS mount: /mnt/shared/dns-alerts.md
  └─ Alert watcher running as service
     └─ Spawns AI agent via OpenClaw

[AI Agent]
  └─ Reads alert file
  └─ Investigates flagged devices
  └─ Posts findings to security dashboard
```

## What Happens After Agent Spawns?

That depends on your security agent's configuration. Example workflow:

1. Agent reads alert details
2. Queries PiHole for full device history
3. Analyzes domain patterns (malware indicators, C2 servers, etc.)
4. Cross-references with threat intel
5. Determines threat level
6. Posts report with recommendations:
   - **Benign:** False positive, tune threshold
   - **Suspicious:** Monitor closely, investigate further
   - **Malicious:** Block device, escalate to human

## License

MIT License - See main project LICENSE

## Questions?

- Main project: See parent directory README
- OpenClaw docs: https://docs.openclaw.ai
- File an issue on GitHub
