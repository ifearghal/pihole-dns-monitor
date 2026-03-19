#!/usr/bin/env python3
"""
Generate mock PiHole logs for testing the monitoring script.
Includes the Meross incident (635k queries from 10.168.168.51).
"""

import datetime
import random
from pathlib import Path

def generate_log_line(timestamp, ip_address, domain, query_type="A"):
    """Generate a PiHole log line in the standard format."""
    # PiHole log format: Feb 20 15:46:00 dnsmasq[123]: query[A] domain.com from 10.168.168.51
    return f"{timestamp.strftime('%b %d %H:%M:%S')} dnsmasq[1234]: query[{query_type}] {domain} from {ip_address}\n"

def generate_mock_logs():
    """Generate mock PiHole logs with realistic traffic patterns."""
    log_dir = Path(__file__).parent / "data"
    log_dir.mkdir(exist_ok=True)
    
    # Normal devices in the network
    normal_devices = {
        "10.168.168.24": "homepc",
        "10.168.168.102": "thinkpad", 
        "10.168.168.38": "prod-server",
        "10.168.168.191": "sandbox",
        "10.168.168.132": "fileserver",
        "10.168.168.51": "meross-plug"  # The problematic device
    }
    
    # Common domains for normal traffic
    normal_domains = [
        "google.com", "github.com", "cloudflare-dns.com", "ubuntu.com",
        "fedoraproject.org", "microsoft.com", "apple.com", "amazon.com",
        "netflix.com", "youtube.com", "facebook.com", "twitter.com"
    ]
    
    # Meross domains (for the storm)
    meross_domains = [
        "iotx-us.meross.com",
        "iot.meross.com", 
        "mqtt-us.meross.com",
        "ntp1.amazon.com",
        "ntp2.amazon.com",
        "time.amazonaws.com"
    ]
    
    # Generate logs for February 19 (yesterday)
    log_file = log_dir / "pihole.log"
    
    with open(log_file, 'w') as f:
        # Start time: Feb 19 00:00
        current_time = datetime.datetime(2026, 2, 19, 0, 0, 0)
        end_time = datetime.datetime(2026, 2, 19, 23, 59, 59)
        
        while current_time <= end_time:
            # Normal traffic: 5-20 queries per minute from each device
            for ip, name in normal_devices.items():
                if ip != "10.168.168.51":  # Not the Meross device
                    # Generate 0-3 queries per device per minute
                    for _ in range(random.randint(0, 3)):
                        domain = random.choice(normal_domains)
                        f.write(generate_log_line(current_time, ip, domain))
            
            # Meross device behavior
            hour = current_time.hour
            
            # Normal behavior: morning and evening
            if hour < 10 or hour > 20:
                # Low activity: 1-5 queries per minute
                for _ in range(random.randint(1, 5)):
                    domain = random.choice(meross_domains)
                    f.write(generate_log_line(current_time, "10.168.168.51", domain))
            
            # THE STORM: 14:00-18:00 (4 hours, ~635k queries)
            elif 14 <= hour <= 18:
                # ~2650 queries per minute to reach 635k in 4 hours
                for _ in range(random.randint(2600, 2700)):
                    # 80% to Meross domains, 20% to Amazon NTP
                    if random.random() < 0.8:
                        domain = random.choice(meross_domains[:3])
                    else:
                        domain = random.choice(meross_domains[3:])
                    f.write(generate_log_line(current_time, "10.168.168.51", domain))
            
            # Normal daytime activity
            else:
                # Moderate activity: 10-30 queries per minute
                for _ in range(random.randint(10, 30)):
                    domain = random.choice(meross_domains)
                    f.write(generate_log_line(current_time, "10.168.168.51", domain))
            
            # Move to next minute
            current_time += datetime.timedelta(minutes=1)
            
            # Progress indicator every hour
            if current_time.minute == 0:
                print(f"Generated logs up to {current_time.strftime('%Y-%m-%d %H:%M')}")
    
    print(f"\nMock log generated: {log_file}")
    print(f"File size: {log_file.stat().st_size / (1024*1024):.1f} MB")
    
    # Generate a smaller test file for quick testing
    test_file = log_dir / "pihole_test.log"
    with open(log_file, 'r') as src, open(test_file, 'w') as dst:
        # Copy just 1 hour of the storm (15:00-16:00)
        for line in src:
            if " 15:" in line:
                dst.write(line)
    
    print(f"Test log generated: {test_file}")
    print(f"File size: {test_file.stat().st_size / (1024*1024):.1f} MB")

if __name__ == "__main__":
    print("Generating mock PiHole logs...")
    generate_mock_logs()
    print("\nDone! Logs include:")
    print("- Normal traffic from 6 devices")
    print("- Meross device storm: ~635k queries between 14:00-18:00")
    print("- Realistic query patterns throughout the day")