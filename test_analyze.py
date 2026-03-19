#!/usr/bin/env python3
"""Quick test script to analyze query patterns"""

import sys
import os
from datetime import datetime
sys.path.insert(0, 'src')

from monitor import PiHoleMonitor

def main():
    monitor = PiHoleMonitor(
        log_path="test_data/pihole.log",
        bulletin_path="/dev/null",
        dry_run=True
    )
    
    # Analyze queries from the end of the log file
    # The logs end at 13:59, so analyze from 13:30-14:00
    analysis_time = datetime.strptime("2026-02-21 13:30", "%Y-%m-%d %H:%M")
    queries = monitor.analyze_queries(analysis_time)
    
    print(f"Total queries: {sum(queries.values())}")
    print(f"Total devices: {len(queries)}")
    print("\nTop 10 devices by query count:")
    
    sorted_devices = sorted(queries.items(), key=lambda x: x[1], reverse=True)
    for i, (device, count) in enumerate(sorted_devices[:10], 1):
        print(f"{i}. {device}: {count:,} queries")

if __name__ == "__main__":
    main()