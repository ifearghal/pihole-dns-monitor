#!/usr/bin/env python3
"""Test anomaly detection by simulating high query device"""

from datetime import datetime
import subprocess

# Create a test log with anomalous activity
test_log = []

# Normal queries from various devices
base_time = datetime.strptime("Feb 21 14:00:00", "%b %d %H:%M:%S")
devices = [
    "10.168.168.50", "10.168.168.55", "10.168.168.120", 
    "10.168.168.130", "10.168.168.190"
]

# Add normal queries
for i in range(30):
    for device in devices:
        test_log.append(f"Feb 21 14:00:{i:02d} dnsmasq[846]: query[A] example.com from {device}\n")

# Add anomalous device with 1500 queries
anomaly_device = "10.168.168.666"
for i in range(1500):
    second = i % 60
    minute = (i // 60) % 30
    test_log.append(f"Feb 21 14:{minute:02d}:{second:02d} dnsmasq[846]: query[A] malware-{i}.com from {anomaly_device}\n")

# Write test log
with open("test_data/anomaly_test.log", "w") as f:
    f.writelines(test_log)

print("Test log created with anomalous device:")
print(f"- Normal devices: 5 devices, ~30 queries each")  
print(f"- Anomaly device ({anomaly_device}): 1,500 queries")

# Run monitor against test log
print("\nRunning monitor...")
result = subprocess.run([
    "python3", "src/monitor.py",
    "--log-path", "test_data/anomaly_test.log",
    "--dry-run",
    "--analysis-time", "2026-02-21 14:00"
], capture_output=True, text=True)

print("\nMonitor output:")
print(result.stdout)
if result.stderr:
    print("Errors:")
    print(result.stderr)