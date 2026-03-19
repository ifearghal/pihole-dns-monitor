# PiHole DNS Query Monitor

Autonomous monitoring system for PiHole DNS servers with anomaly detection and automated security response.

## Overview

This project monitors PiHole DNS query logs in real-time to detect unusual patterns that might indicate:
- Compromised devices making excessive DNS requests
- Malware beaconing
- IoT device misconfigurations
- DNS tunneling attempts

When anomalies are detected, the system automatically:
1. Logs the anomaly to a monitoring dashboard
2. Triggers security analysis (optional AI agent integration)
3. Provides detailed device/query breakdowns for investigation

## Features

- **Real-time monitoring** - Analyzes DNS queries every 15-30 minutes
- **Anomaly detection** - Configurable thresholds for query volume
- **Zero-dependency** - Uses only Python 3 standard library
- **Safe operation** - Read-only access to PiHole logs
- **Comprehensive testing** - 32 security-focused unit tests
- **Event-driven alerts** - Optional file watcher for instant response
- **AI agent integration** - Spawn security analysis agents on detection

## Architecture

### Core Monitor (PiHole Server)

Runs on your PiHole server via cron, analyzing DNS query logs:

```
pihole-monitor/
├── src/
│   └── monitor.py          # Main monitoring script
├── test/
│   ├── test_security.py    # Security test suite
│   └── data/               # Mock PiHole logs for testing
├── requirements.txt        # Test dependencies only
└── run_monitor.sh         # Cron wrapper script
```

### Alert Watcher (Optional - AI Integration)

Watches for alert files and triggers automated security response:

```
alert-watcher/
├── dns-alert-watcher.sh   # File watcher + agent spawner
└── README.md              # Alert watcher documentation
```

## Quick Start

### 1. Install on PiHole Server

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/pihole-dns-monitor.git
cd pihole-dns-monitor

# Test with your PiHole logs
python3 src/monitor.py --dry-run

# Set up cron job (every 30 minutes)
crontab -e
# Add: */30 * * * * /path/to/pihole-dns-monitor/run_monitor.sh
```

### 2. Configure Thresholds

Edit `monitor.conf` (or use command-line args):

```bash
# Default threshold: 2500 queries per device in 30 minutes
python3 src/monitor.py --threshold 2500

# Customize analysis window
python3 src/monitor.py --window-minutes 15
```

### 3. Set Up Alerts

Choose your alert method:

**Option A: Simple file alerts**
```bash
# Monitor writes alerts to a file you can check
python3 src/monitor.py --alert-file /path/to/alerts.txt
```

**Option B: AI-powered response (requires OpenClaw)**
```bash
# See alert-watcher/ for automatic security agent spawning
cd alert-watcher
./dns-alert-watcher.sh
```

## Usage

### Basic Monitoring

```bash
# Monitor with default settings
python3 src/monitor.py

# Test mode (no alerts)
python3 src/monitor.py --dry-run

# Custom PiHole log location
python3 src/monitor.py --log-path /var/log/pihole.log
```

### Advanced Options

```bash
# Analyze specific time window
python3 src/monitor.py --analysis-time "2026-03-18 14:00"

# Custom threshold and output
python3 src/monitor.py \
  --threshold 1000 \
  --window-minutes 15 \
  --alert-file /mnt/shared/dns-alerts.log
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--log-path` | PiHole log file location | `/var/log/pihole/pihole.log` |
| `--threshold` | Queries/device to trigger alert | `2500` |
| `--window-minutes` | Analysis window size | `30` |
| `--alert-file` | Where to write alerts | `dns-alerts.log` |
| `--dry-run` | Test without writing alerts | `false` |
| `--analysis-time` | Analyze specific time window | Current time |

## Testing

### Run Security Tests

```bash
# Install test dependencies
pip install -r requirements.txt

# Run all tests
python3 -m pytest test/ -v

# With coverage report
python3 -m pytest test/ --cov=src --cov-report=html
```

### Test Coverage

✅ **32 security-focused unit tests** covering:
- Path traversal protection
- Output sanitization & injection prevention
- IP/domain validation
- DoS protection (line length limits)
- Alert deduplication
- Timestamp parsing & year rollover
- Resource limits

See [TESTING.md](TESTING.md) for detailed test documentation.

## Real-World Example

### The IoT Device Storm

After deploying this system, we discovered an iPhone making 1,200+ DNS queries in 30 minutes - something that looked like malware at first glance. The monitor detected it instantly:

```
🔴 DNS QUERY ANOMALY DETECTED
Window: 14:00 - 14:30
Device: 10.xxx.xxx.xxx (1,247 queries, 41.6/min)
Top domains:
  - apple-finance.query.itsn.apple.com (380 queries)
  - apple.com (290 queries)
  - icloud.com (245 queries)
```

Turns out it was just iOS doing aggressive widget refreshes. We tuned the threshold from 1,000 → 2,500 queries/30min to reduce false positives while still catching actual issues.

## AI Agent Integration (Optional)

The `alert-watcher/` component enables event-driven security response:

1. **Monitor detects anomaly** → Writes alert file
2. **File watcher detects change** → Spawns security agent
3. **AI agent investigates** → Analyzes patterns, identifies threats
4. **Report generated** → Recommendations for action

Requires [OpenClaw](https://openclaw.ai) or similar AI agent framework.

See `alert-watcher/README.md` for setup instructions.

## Safety Features

- ✅ **Read-only** - Never modifies PiHole configuration
- ✅ **Zero dependencies** - Core monitor uses only Python stdlib
- ✅ **Graceful failure** - Errors don't crash the monitor
- ✅ **Dry-run mode** - Test before deploying
- ✅ **Path traversal protection** - Validated file paths
- ✅ **Input sanitization** - All external data validated

## Deployment Checklist

- [ ] Test with `--dry-run` on your PiHole logs
- [ ] Verify alert file location is accessible
- [ ] Set appropriate threshold for your network size
- [ ] Configure cron job (recommended: every 30 minutes)
- [ ] Monitor for false positives in first 24-48 hours
- [ ] Tune threshold based on your baseline traffic
- [ ] (Optional) Set up alert watcher for AI response

## Requirements

- **Python 3.7+** (standard library only for core monitor)
- **PiHole** with accessible log files
- **File system access** for reading logs and writing alerts
- **(Optional)** OpenClaw for AI agent integration

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please:
1. Run security tests before submitting PRs
2. Maintain zero-dependency core (stdlib only)
3. Add tests for new features
4. Update documentation

## Acknowledgments

Built as part of a home infrastructure security project. Inspired by the need for autonomous DNS monitoring that doesn't require constant human oversight.

Special thanks to the PiHole team for making DNS monitoring accessible.

---

**Questions? Issues?** Open a GitHub issue or discussion.
