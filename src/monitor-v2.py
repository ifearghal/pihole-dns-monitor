#!/usr/bin/env python3
"""
PiHole DNS Query Monitor v3
Detects anomalous query patterns and posts alerts to the bulletin board.

Author: PiHole DNS Monitor Contributors
Project: PiHole DNS Monitoring
Version: 3.0.0 - Edge Case Fixes

SECURITY IMPROVEMENTS:
- Path traversal protection with parent directory validation
- Output sanitization to prevent bulletin board injection
- Resource limits on file reading (size and line count)
- Proper IP address validation using ipaddress module
- File locking to prevent concurrent write corruption (Unix only)
- Bulletin board rotation to prevent disk exhaustion

OPERATIONAL IMPROVEMENTS:
- Configuration file support
- File logging with rotation
- Proper error handling with specific exceptions
- Year rollover fix in timestamp parsing
- Startup validation
- Debug mode for troubleshooting
- Platform compatibility (Unix/Windows)

v3.0.0 EDGE CASE FIXES:
- Platform-aware file locking (graceful fallback on Windows)
- Fixed config threshold loading (instance vars instead of globals)
- Improved output sanitization (no HTML escaping for markdown)
- Cleaned up symlink warning
- Robust alert fingerprinting
"""

import re
import argparse
import logging
from logging.handlers import RotatingFileHandler
import configparser
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
import sys
import ipaddress
import json
import os

# Platform-specific imports
HAS_FLOCK = sys.platform != 'win32'
if HAS_FLOCK:
    import fcntl

# Constants
QUERY_THRESHOLD = 1000  # Alert if device exceeds this in 30 minutes
WINDOW_MINUTES = 30     # Rolling window size
MAX_LOG_SIZE = 100 * 1024 * 1024  # 100 MB max log file size
MAX_LINES = 1_000_000  # Maximum lines to process (safety limit)
MAX_LINE_LENGTH = 2048  # Maximum log line length
MAX_BULLETIN_SIZE = 10 * 1024 * 1024  # 10 MB max bulletin board size
ALERT_COOLDOWN_SECONDS = 300  # 5 minutes between duplicate alerts
MAX_DOMAIN_LENGTH = 253  # RFC 1035

# Log pattern with more restrictive IP address matching
LOG_PATTERN = re.compile(
    r'^(\w+ \d+ \d+:\d+:\d+) dnsmasq\[\d+\]: query\[([A-Z]+)\] (.+) from ([\w.:]+)$'
)


class PiHoleMonitor:
    """Monitor PiHole logs for anomalous query patterns."""
    
    def __init__(self, log_path, bulletin_path, log_file=None, 
                 allowed_log_dir=None, allowed_bulletin_dir=None, dry_run=False,
                 query_threshold=None, window_minutes=None):
        """Initialize the monitor with security validations.
        
        Args:
            log_path: Path to PiHole log file
            bulletin_path: Path to bulletin board file
            log_file: Path to monitor's log file (optional)
            allowed_log_dir: Parent directory for log_path validation (security)
            allowed_bulletin_dir: Parent directory for bulletin_path validation (security)
            dry_run: If True, don't write to bulletin board
            query_threshold: Alert threshold (default: QUERY_THRESHOLD constant)
            window_minutes: Analysis window size (default: WINDOW_MINUTES constant)
        """
        self.dry_run = dry_run
        self.query_threshold = query_threshold or QUERY_THRESHOLD
        self.window_minutes = window_minutes or WINDOW_MINUTES
        self.logger = self._setup_logging(log_file)
        
        # Validate and set paths with security checks
        self.log_path = self._validate_path(
            log_path, 
            allowed_log_dir or '/var/log',
            mode='r',
            description="PiHole log"
        )
        
        self.bulletin_path = self._validate_path(
            bulletin_path,
            allowed_bulletin_dir or os.path.expanduser('~'),
            mode='w',
            description="Bulletin board"
        )
        
        self.alert_cache_path = self.bulletin_path.parent / '.pihole-monitor-cache.json'
        self.alert_history = self._load_alert_history()
        
        self.logger.info(f"Monitor initialized: log={self.log_path}, bulletin={self.bulletin_path}")
        
    def _validate_path(self, path, allowed_parent, mode='r', description="file"):
        """Validate that path is within expected directory (SECURITY).
        
        This prevents path traversal attacks via command-line arguments.
        
        Args:
            path: Path to validate
            allowed_parent: Parent directory that path must be within
            mode: 'r' for read, 'w' for write
            description: Description for error messages
            
        Returns:
            Path: Validated absolute path
            
        Raises:
            ValueError: If path is outside allowed directory or invalid
            FileNotFoundError: If path doesn't exist (mode='r')
        """
        try:
            # Resolve to absolute path (follows symlinks)
            path_obj = Path(path).resolve()
            allowed_obj = Path(allowed_parent).resolve()
            
            # Check if path is within allowed directory
            try:
                # Will raise ValueError if path is not relative to allowed_obj
                path_obj.relative_to(allowed_obj)
            except ValueError:
                raise ValueError(
                    f"Security: {description} path {path_obj} is outside "
                    f"allowed directory {allowed_obj}"
                )
            
            # Mode-specific validation
            if mode == 'r':
                if not path_obj.is_file():
                    raise FileNotFoundError(f"{description} not found: {path_obj}")
                if not os.access(path_obj, os.R_OK):
                    raise PermissionError(f"Cannot read {description}: {path_obj}")
                    
            elif mode == 'w':
                # For write mode, check parent directory exists and is writable
                parent = path_obj.parent
                if not parent.exists():
                    raise FileNotFoundError(f"Parent directory for {description} not found: {parent}")
                if not os.access(parent, os.W_OK):
                    raise PermissionError(f"Cannot write to {description} directory: {parent}")
            
            return path_obj
            
        except Exception as e:
            self.logger.error(f"Path validation failed for {description}: {e}")
            raise
        
    def _setup_logging(self, log_file=None):
        """Configure logging with console and optional file output.
        
        Args:
            log_file: Path to log file (optional)
            
        Returns:
            logging.Logger: Configured logger
        """
        logger = logging.getLogger('pihole-monitor')
        logger.setLevel(logging.INFO)
        
        # Clear any existing handlers
        logger.handlers = []
        
        # Console handler
        console = logging.StreamHandler()
        console_fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console.setFormatter(console_fmt)
        logger.addHandler(console)
        
        # File handler with rotation (if specified)
        if log_file:
            try:
                log_path = Path(log_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                
                file_handler = RotatingFileHandler(
                    log_file,
                    maxBytes=10*1024*1024,  # 10 MB
                    backupCount=5
                )
                file_fmt = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                file_handler.setFormatter(file_fmt)
                logger.addHandler(file_handler)
                
            except Exception as e:
                # Don't fail if file logging setup fails, just warn
                print(f"Warning: Could not set up file logging: {e}", file=sys.stderr)
        
        return logger
    
    def _load_alert_history(self):
        """Load alert history from cache file for duplicate detection."""
        if not self.alert_cache_path.exists():
            return {}
        
        try:
            with open(self.alert_cache_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.warning(f"Could not load alert cache: {e}")
            return {}
    
    def _save_alert_history(self):
        """Save alert history to cache file."""
        try:
            with open(self.alert_cache_path, 'w') as f:
                json.dump(self.alert_history, f)
        except Exception as e:
            self.logger.warning(f"Could not save alert cache: {e}")
    
    def _sanitize_output(self, text):
        """Sanitize text for safe inclusion in bulletin board (SECURITY).
        
        Prevents injection attacks via malicious log data.
        
        Args:
            text: Text to sanitize
            
        Returns:
            str: Sanitized text safe for bulletin board
        """
        if not isinstance(text, str):
            text = str(text)
        
        # Remove control characters (except newline and tab)
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\t')
        
        # Limit length to prevent bulletin board pollution
        max_length = 100
        if len(text) > max_length:
            text = text[:max_length] + "..."
        
        return text
        
    def parse_log_line(self, line):
        """Parse a PiHole log line with validation.
        
        Returns:
            tuple: (timestamp, query_type, domain, ip_address) or None if parse fails
        """
        # Limit line length to prevent DoS (SECURITY)
        if len(line) > MAX_LINE_LENGTH:
            self.logger.debug(f"Line too long ({len(line)} chars), skipping")
            return None
        
        match = LOG_PATTERN.match(line.strip())
        if not match:
            return None
            
        timestamp_str, query_type, domain, ip_address = match.groups()
        
        # Validate IP address (SECURITY)
        try:
            # Try parsing as IPv4 or IPv6
            ipaddress.ip_address(ip_address)
        except ValueError:
            # If not valid IP, log and skip
            self.logger.debug(f"Invalid IP address: {ip_address}")
            return None
        
        # Validate domain length (SECURITY)
        if len(domain) > MAX_DOMAIN_LENGTH:
            self.logger.debug(f"Domain too long ({len(domain)} chars)")
            return None
        
        # Parse timestamp with year inference (FIX: year rollover bug)
        try:
            now = datetime.now()
            current_year = now.year
            
            # Try current year first
            timestamp = datetime.strptime(
                f"{current_year} {timestamp_str}",
                "%Y %b %d %H:%M:%S"
            )
            
            # If timestamp is more than 1 day in the future, it's from last year
            # This handles the case where we're in Jan 1 reading Dec 31 logs
            if timestamp > now + timedelta(days=1):
                timestamp = timestamp.replace(year=current_year - 1)
                
        except ValueError as e:
            self.logger.debug(f"Failed to parse timestamp '{timestamp_str}': {e}")
            return None
            
        return timestamp, query_type, domain, ip_address
        
    def analyze_queries(self, start_time=None):
        """Analyze queries in the specified time window.
        
        Args:
            start_time: Start of analysis window (default: window_minutes ago)
            
        Returns:
            dict: {ip_address: query_count} for the window
        """
        if start_time is None:
            start_time = datetime.now() - timedelta(minutes=self.window_minutes)
            
        end_time = start_time + timedelta(minutes=self.window_minutes)
        query_counts = defaultdict(int)
        
        # Check file size before reading (SECURITY: prevent resource exhaustion)
        try:
            file_size = self.log_path.stat().st_size
            if file_size > MAX_LOG_SIZE:
                self.logger.error(
                    f"Log file too large: {file_size:,} bytes (max {MAX_LOG_SIZE:,}). "
                    f"Consider using log rotation or increasing MAX_LOG_SIZE."
                )
                return query_counts
        except OSError as e:
            self.logger.error(f"Cannot stat log file {self.log_path}: {e}")
            return query_counts
        
        # Read and parse log file with safety limits
        try:
            lines_processed = 0
            
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    lines_processed += 1
                    
                    # Safety limit: don't process more than MAX_LINES (SECURITY)
                    if lines_processed > MAX_LINES:
                        self.logger.warning(
                            f"Reached max line limit ({MAX_LINES:,}), stopping read"
                        )
                        break
                    
                    parsed = self.parse_log_line(line)
                    if not parsed:
                        continue
                        
                    timestamp, _, _, ip_address = parsed
                    
                    # Check if query is within our window
                    if start_time <= timestamp < end_time:
                        query_counts[ip_address] += 1
            
            self.logger.debug(f"Processed {lines_processed:,} log lines")
                        
        except FileNotFoundError:
            self.logger.error(f"Log file not found: {self.log_path}")
            raise
        except PermissionError:
            self.logger.error(
                f"Permission denied reading {self.log_path}. "
                f"Check file permissions and user/group membership."
            )
            raise
        except OSError as e:
            self.logger.error(
                f"I/O error reading log file: {e}. "
                f"Check disk space and file system health."
            )
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error reading log: {e}", exc_info=True)
            raise
            
        return query_counts
        
    def detect_anomalies(self, query_counts):
        """Detect devices with anomalous query counts.
        
        Args:
            query_counts: dict of {ip_address: count}
            
        Returns:
            list: [(ip_address, count)] for devices exceeding threshold
        """
        anomalies = []
        
        for ip_address, count in query_counts.items():
            if count > self.query_threshold:
                anomalies.append((ip_address, count))
                
        # Sort by query count (highest first)
        anomalies.sort(key=lambda x: x[1], reverse=True)
        
        return anomalies
    
    def _is_duplicate_alert(self, anomalies):
        """Check if this alert is a duplicate of a recent one.
        
        Args:
            anomalies: List of (ip, count) tuples
            
        Returns:
            bool: True if this is a duplicate alert
        """
        if not anomalies:
            return False
        
        # Create fingerprint of alert (set of IPs)
        alert_ips = sorted(ip for ip, _ in anomalies)
        alert_fingerprint = ','.join(alert_ips)
        
        # Check if we've seen this fingerprint recently
        now = datetime.now().timestamp()
        
        if alert_fingerprint in self.alert_history:
            last_alert_time = self.alert_history[alert_fingerprint]
            if now - last_alert_time < ALERT_COOLDOWN_SECONDS:
                return True
        
        # Update history
        self.alert_history[alert_fingerprint] = now
        
        # Clean old entries (older than 24 hours)
        cutoff = now - 86400
        self.alert_history = {
            k: v for k, v in self.alert_history.items() 
            if v > cutoff
        }
        
        self._save_alert_history()
        return False
    
    def _rotate_bulletin_board(self):
        """Rotate bulletin board when it gets too large."""
        try:
            backup_path = self.bulletin_path.with_suffix('.md.old')
            
            # If backup exists, remove it
            if backup_path.exists():
                backup_path.unlink()
            
            # Rename current to backup
            self.bulletin_path.rename(backup_path)
            self.logger.info(f"Rotated bulletin board to {backup_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to rotate bulletin board: {e}")
            
    def post_alert(self, anomalies, window_start):
        """Post alert to bulletin board with safety limits.
        
        Args:
            anomalies: list of (ip_address, count) tuples
            window_start: start time of the analysis window
        """
        if not anomalies:
            return
        
        # Check for duplicate alerts (SECURITY: prevent spam)
        if self._is_duplicate_alert(anomalies):
            self.logger.info(
                f"Duplicate alert suppressed ({len(anomalies)} devices). "
                f"Cooldown: {ALERT_COOLDOWN_SECONDS}s"
            )
            return
        
        # Check bulletin board size (SECURITY: prevent disk exhaustion)
        if self.bulletin_path.exists():
            try:
                current_size = self.bulletin_path.stat().st_size
                if current_size > MAX_BULLETIN_SIZE:
                    self.logger.warning(
                        f"Bulletin board too large ({current_size:,} bytes), rotating"
                    )
                    self._rotate_bulletin_board()
            except OSError as e:
                self.logger.warning(f"Could not check bulletin board size: {e}")
        
        # Build alert message
        window_end = window_start + timedelta(minutes=self.window_minutes)
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        
        alert_lines = [f"[{timestamp_str}] PiHole Monitor: 🔴 **DNS QUERY ANOMALY DETECTED**"]
        alert_lines.append(
            f"Window: {window_start.strftime('%H:%M')} - {window_end.strftime('%H:%M')}"
        )
        alert_lines.append(
            f"Threshold: >{self.query_threshold:,} queries in {self.window_minutes} minutes"
        )
        alert_lines.append("")
        alert_lines.append("Anomalous devices:")
        
        # Limit to top 10 devices (SECURITY: prevent bulletin pollution)
        for ip_address, count in anomalies[:10]:
            # Sanitize IP address (SECURITY: prevent injection)
            safe_ip = self._sanitize_output(ip_address)
            rate = count / self.window_minutes
            alert_lines.append(f"- {safe_ip}: {count:,} queries ({rate:.1f}/min)")
        
        if len(anomalies) > 10:
            alert_lines.append(f"... and {len(anomalies) - 10} more devices")
            
        alert_lines.append("")
        alert_lines.append("Recommend investigating these devices for malware/misconfiguration.")
        
        alert_message = "\n".join(alert_lines)
        
        if self.dry_run:
            self.logger.info("DRY RUN - Would post to bulletin board:")
            print(alert_message)
        else:
            try:
                # Write with file locking (SECURITY: prevent race conditions)
                # Note: File locking only available on Unix platforms
                with open(self.bulletin_path, 'a', encoding='utf-8') as f:
                    # Acquire exclusive lock (Unix only)
                    if HAS_FLOCK:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    try:
                        f.write("\n" + alert_message + "\n")
                        f.flush()  # Ensure data is written
                        self.logger.info(f"Alert posted to bulletin board ({len(anomalies)} devices)")
                    finally:
                        # Release lock (Unix only)
                        if HAS_FLOCK:
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                        
            except PermissionError:
                self.logger.error(
                    f"Permission denied writing to {self.bulletin_path}. "
                    f"Check file permissions."
                )
                raise
            except OSError as e:
                self.logger.error(
                    f"I/O error writing to bulletin board: {e}. "
                    f"Check disk space."
                )
                raise
            except Exception as e:
                self.logger.error(f"Failed to post alert: {e}", exc_info=True)
                raise
                
    def run(self, analysis_time=None):
        """Run the monitor for a specific time window.
        
        Args:
            analysis_time: Time to analyze (default: current time - window_minutes)
        """
        if analysis_time is None:
            # Analyze the previous window
            analysis_time = datetime.now() - timedelta(minutes=self.window_minutes)
            
        self.logger.info(
            f"Analyzing queries from {analysis_time.strftime('%Y-%m-%d %H:%M')}"
        )
        
        # Analyze queries
        query_counts = self.analyze_queries(analysis_time)
        
        if not query_counts:
            self.logger.warning("No queries found in analysis window")
            return
            
        # Log summary
        total_queries = sum(query_counts.values())
        self.logger.info(
            f"Found {total_queries:,} total queries from {len(query_counts)} devices"
        )
        
        # Detect anomalies
        anomalies = self.detect_anomalies(query_counts)
        
        if anomalies:
            self.logger.warning(f"Detected {len(anomalies)} anomalous device(s)")
            self.post_alert(anomalies, analysis_time)
        else:
            self.logger.info("No anomalies detected")


def load_config(config_file):
    """Load configuration from INI file.
    
    Args:
        config_file: Path to config file
        
    Returns:
        dict: Configuration values
    """
    config = configparser.ConfigParser()
    config.read(config_file)
    
    result = {}
    
    # Paths section
    if 'paths' in config:
        result['log_path'] = config['paths'].get('log_path')
        result['bulletin_path'] = config['paths'].get('bulletin_path')
        result['monitor_log'] = config['paths'].get('monitor_log')
        result['allowed_log_dir'] = config['paths'].get('allowed_log_dir')
        result['allowed_bulletin_dir'] = config['paths'].get('allowed_bulletin_dir')
    
    # Thresholds section (optional)
    if 'thresholds' in config:
        result['query_threshold'] = config['thresholds'].getint('query_threshold', QUERY_THRESHOLD)
        result['window_minutes'] = config['thresholds'].getint('window_minutes', WINDOW_MINUTES)
    
    return result


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor PiHole logs for anomalies (v3.0 - Edge Case Fixes)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with config file
  %(prog)s --config /etc/pihole-monitor/monitor.conf
  
  # Run with explicit paths
  %(prog)s --log-path /var/log/pihole/pihole.log \\
           --bulletin-path /var/alerts/dns.md
  
  # Dry run for testing
  %(prog)s --config monitor.conf --dry-run --verbose
  
  # Analyze specific time window
  %(prog)s --config monitor.conf --analysis-time "2026-02-20 14:30"
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        help='Path to configuration file (INI format)'
    )
    parser.add_argument(
        '--log-path',
        help='Path to PiHole log file (overrides config)'
    )
    parser.add_argument(
        '--bulletin-path',
        help='Path to bulletin board file (overrides config)'
    )
    parser.add_argument(
        '--monitor-log',
        help='Path to monitor log file (overrides config)'
    )
    parser.add_argument(
        '--allowed-log-dir',
        help='Parent directory for log path validation (security)'
    )
    parser.add_argument(
        '--allowed-bulletin-dir',
        help='Parent directory for bulletin path validation (security)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Test mode - don\'t post alerts'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output for debugging'
    )
    parser.add_argument(
        '--analysis-time',
        help='Specific time to analyze (YYYY-MM-DD HH:MM)'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 3.0.0'
    )
    
    args = parser.parse_args()
    
    # Load config file if specified
    config = {}
    if args.config:
        try:
            config = load_config(args.config)
        except Exception as e:
            print(f"Error loading config file: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Command-line args override config file
    log_path = args.log_path or config.get('log_path')
    bulletin_path = args.bulletin_path or config.get('bulletin_path')
    monitor_log = args.monitor_log or config.get('monitor_log')
    allowed_log_dir = args.allowed_log_dir or config.get('allowed_log_dir')
    allowed_bulletin_dir = args.allowed_bulletin_dir or config.get('allowed_bulletin_dir')
    query_threshold = config.get('query_threshold')  # None if not in config
    window_minutes = config.get('window_minutes')  # None if not in config
    
    # Validate required arguments
    if not log_path:
        parser.error("--log-path is required (or specify in config file)")
    if not bulletin_path:
        parser.error("--bulletin-path is required (or specify in config file)")
    
    # Parse and validate analysis time
    analysis_time = None
    if args.analysis_time:
        try:
            analysis_time = datetime.strptime(args.analysis_time, "%Y-%m-%d %H:%M")
            
            # Validate time is within reasonable bounds (SECURITY)
            now = datetime.now()
            max_past = now - timedelta(days=7)
            max_future = now + timedelta(hours=1)
            
            if analysis_time < max_past:
                parser.error("Analysis time too far in past (max 7 days)")
            if analysis_time > max_future:
                parser.error("Analysis time cannot be in the future")
                
        except ValueError:
            parser.error(
                f"Invalid time format: {args.analysis_time}. "
                f"Use format: YYYY-MM-DD HH:MM"
            )
    
    # Create and run monitor
    try:
        monitor = PiHoleMonitor(
            log_path,
            bulletin_path,
            log_file=monitor_log,
            allowed_log_dir=allowed_log_dir,
            allowed_bulletin_dir=allowed_bulletin_dir,
            dry_run=args.dry_run,
            query_threshold=query_threshold,
            window_minutes=window_minutes
        )
        
        # Set verbose logging if requested
        if args.verbose:
            monitor.logger.setLevel(logging.DEBUG)
            monitor.logger.debug("Verbose mode enabled")
        
        monitor.run(analysis_time)
        
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("\nCheck that all required files and directories exist.", file=sys.stderr)
        sys.exit(1)
    except PermissionError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("\nCheck file permissions and user/group membership.", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
