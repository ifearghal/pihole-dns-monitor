#!/usr/bin/env python3
"""
PiHole DNS Query Monitor
Detects anomalous query patterns and posts alerts to the bulletin board.

Author: PiHole DNS Monitor

"""

import re
import argparse
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
import sys

# Constants
QUERY_THRESHOLD = 1000  # Alert if device exceeds this in 30 minutes
WINDOW_MINUTES = 30     # Rolling window size
LOG_PATTERN = re.compile(
    r'^(\w+ \d+ \d+:\d+:\d+) dnsmasq\[\d+\]: query\[([A-Z]+)\] (.+) from (.+)$'
)

class PiHoleMonitor:
    """Monitor PiHole logs for anomalous query patterns."""
    
    def __init__(self, log_path, bulletin_path, dry_run=False):
        self.log_path = Path(log_path)
        self.bulletin_path = Path(bulletin_path)
        self.dry_run = dry_run
        self.logger = self._setup_logging()
        
    def _setup_logging(self):
        """Configure logging."""
        logger = logging.getLogger('pihole-monitor')
        logger.setLevel(logging.INFO)
        
        # Console handler
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
        
    def parse_log_line(self, line):
        """Parse a PiHole log line.
        
        Returns:
            tuple: (timestamp, query_type, domain, ip_address) or None if parse fails
        """
        match = LOG_PATTERN.match(line.strip())
        if not match:
            return None
            
        timestamp_str, query_type, domain, ip_address = match.groups()
        
        # Parse timestamp (assuming current year)
        try:
            # PiHole logs don't include year, so we use current year
            timestamp = datetime.strptime(
                f"{datetime.now().year} {timestamp_str}", 
                "%Y %b %d %H:%M:%S"
            )
        except ValueError:
            return None
            
        return timestamp, query_type, domain, ip_address
        
    def analyze_queries(self, start_time=None):
        """Analyze queries in the specified time window.
        
        Args:
            start_time: Start of analysis window (default: 30 minutes ago)
            
        Returns:
            dict: {ip_address: query_count} for the window
        """
        if start_time is None:
            start_time = datetime.now() - timedelta(minutes=WINDOW_MINUTES)
            
        end_time = start_time + timedelta(minutes=WINDOW_MINUTES)
        query_counts = defaultdict(int)
        
        if not self.log_path.exists():
            self.logger.error(f"Log file not found: {self.log_path}")
            return query_counts
            
        try:
            with open(self.log_path, 'r') as f:
                for line in f:
                    parsed = self.parse_log_line(line)
                    if not parsed:
                        continue
                        
                    timestamp, _, _, ip_address = parsed
                    
                    # Check if query is within our window
                    if start_time <= timestamp < end_time:
                        query_counts[ip_address] += 1
                        
        except Exception as e:
            self.logger.error(f"Error reading log file: {e}")
            
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
            if count > QUERY_THRESHOLD:
                anomalies.append((ip_address, count))
                
        # Sort by query count (highest first)
        anomalies.sort(key=lambda x: x[1], reverse=True)
        
        return anomalies
        
    def post_alert(self, anomalies, window_start):
        """Post alert to bulletin board.
        
        Args:
            anomalies: list of (ip_address, count) tuples
            window_start: start time of the analysis window
        """
        if not anomalies:
            return
            
        window_end = window_start + timedelta(minutes=WINDOW_MINUTES)
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        
        # Build alert message
        alert_lines = [f"[{timestamp_str}] Monitor: 🔴 **DNS QUERY ANOMALY DETECTED**"]
        alert_lines.append(f"Window: {window_start.strftime('%H:%M')} - {window_end.strftime('%H:%M')}")
        alert_lines.append(f"Threshold: >{QUERY_THRESHOLD:,} queries in {WINDOW_MINUTES} minutes")
        alert_lines.append("")
        alert_lines.append("Anomalous devices:")
        
        for ip_address, count in anomalies:
            alert_lines.append(f"- {ip_address}: {count:,} queries ({count/WINDOW_MINUTES:.1f}/min)")
            
        alert_lines.append("")
        alert_lines.append("Recommend investigating these devices for malware/misconfiguration.")
        
        alert_message = "\n".join(alert_lines)
        
        if self.dry_run:
            self.logger.info("DRY RUN - Would post to bulletin board:")
            print(alert_message)
        else:
            try:
                with open(self.bulletin_path, 'a') as f:
                    f.write("\n" + alert_message + "\n")
                self.logger.info("Alert posted to bulletin board")
            except Exception as e:
                self.logger.error(f"Failed to post alert: {e}")
                
    def run(self, analysis_time=None):
        """Run the monitor for a specific time window.
        
        Args:
            analysis_time: Time to analyze (default: current time - 30 minutes)
        """
        if analysis_time is None:
            # Analyze the previous 30-minute window
            analysis_time = datetime.now() - timedelta(minutes=WINDOW_MINUTES)
            
        self.logger.info(f"Analyzing queries from {analysis_time.strftime('%Y-%m-%d %H:%M')}")
        
        # Analyze queries
        query_counts = self.analyze_queries(analysis_time)
        
        if not query_counts:
            self.logger.warning("No queries found in analysis window")
            return
            
        # Log summary
        total_queries = sum(query_counts.values())
        self.logger.info(f"Found {total_queries:,} total queries from {len(query_counts)} devices")
        
        # Detect anomalies
        anomalies = self.detect_anomalies(query_counts)
        
        if anomalies:
            self.logger.warning(f"Detected {len(anomalies)} anomalous device(s)")
            self.post_alert(anomalies, analysis_time)
        else:
            self.logger.info("No anomalies detected")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Monitor PiHole logs for anomalies")
    parser.add_argument(
        '--log-path', 
        default='/var/log/pihole/pihole.log',
        help='Path to PiHole log file'
    )
    parser.add_argument(
        '--bulletin-path',
        default='/var/log/dns-alerts.md',
        help='Path to bulletin board file'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Test mode - don\'t post alerts'
    )
    parser.add_argument(
        '--analysis-time',
        help='Specific time to analyze (YYYY-MM-DD HH:MM)'
    )
    
    args = parser.parse_args()
    
    # Parse analysis time if provided
    analysis_time = None
    if args.analysis_time:
        try:
            analysis_time = datetime.strptime(args.analysis_time, "%Y-%m-%d %H:%M")
        except ValueError:
            print(f"Invalid time format: {args.analysis_time}")
            print("Use format: YYYY-MM-DD HH:MM")
            sys.exit(1)
    
    # Create and run monitor
    monitor = PiHoleMonitor(args.log_path, args.bulletin_path, args.dry_run)
    monitor.run(analysis_time)


if __name__ == "__main__":
    main()