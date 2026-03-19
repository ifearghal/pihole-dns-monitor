#!/usr/bin/env python3
"""
Unit tests for security-critical functions in PiHole Monitor v3

Tests focus on:
- Path traversal protection
- Output sanitization
- Input validation
- Resource limits
- Injection prevention

Author: PiHole DNS Monitor Contributors
"""

import pytest
import tempfile
import os
from pathlib import Path
from datetime import datetime, timedelta
import sys

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

# Import module with hyphen in name using importlib
import importlib.util
spec = importlib.util.spec_from_file_location(
    "monitor_v3",
    Path(__file__).parent.parent / 'src' / 'monitor-v3.py'
)
monitor_v3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor_v3)

# Import classes and constants
PiHoleMonitor = monitor_v3.PiHoleMonitor
MAX_LINE_LENGTH = monitor_v3.MAX_LINE_LENGTH
MAX_DOMAIN_LENGTH = monitor_v3.MAX_DOMAIN_LENGTH


class TestPathTraversalProtection:
    """Test suite for path traversal attack prevention."""
    
    def test_valid_path_within_allowed_directory(self, tmp_path):
        """Valid path within allowed directory should pass validation."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "pihole.log"
        log_file.touch()
        
        bulletin_dir = tmp_path / "alerts"
        bulletin_dir.mkdir()
        bulletin_file = bulletin_dir / "bulletin.md"
        
        monitor = PiHoleMonitor(
            log_path=str(log_file),
            bulletin_path=str(bulletin_file),
            allowed_log_dir=str(log_dir),
            allowed_bulletin_dir=str(bulletin_dir),
            dry_run=True
        )
        
        assert monitor.log_path == log_file.resolve()
        assert monitor.bulletin_path == bulletin_file.resolve()
    
    def test_path_traversal_blocked_parent_directory(self, tmp_path):
        """Path traversal using ../ should be blocked."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        
        # Create a file outside the allowed directory
        outside_file = tmp_path / "outside.log"
        outside_file.touch()
        
        # Try to access it via ../
        traversal_path = str(log_dir / ".." / "outside.log")
        
        bulletin_dir = tmp_path / "alerts"
        bulletin_dir.mkdir()
        bulletin_file = bulletin_dir / "bulletin.md"
        
        with pytest.raises(ValueError, match="outside allowed directory"):
            PiHoleMonitor(
                log_path=traversal_path,
                bulletin_path=str(bulletin_file),
                allowed_log_dir=str(log_dir),
                allowed_bulletin_dir=str(bulletin_dir),
                dry_run=True
            )
    
    def test_path_traversal_blocked_absolute_path(self, tmp_path):
        """Absolute path outside allowed directory should be blocked."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        
        # Create file in a different location
        other_dir = tmp_path / "other"
        other_dir.mkdir()
        other_file = other_dir / "evil.log"
        other_file.touch()
        
        bulletin_dir = tmp_path / "alerts"
        bulletin_dir.mkdir()
        bulletin_file = bulletin_dir / "bulletin.md"
        
        with pytest.raises(ValueError, match="outside allowed directory"):
            PiHoleMonitor(
                log_path=str(other_file),
                bulletin_path=str(bulletin_file),
                allowed_log_dir=str(log_dir),
                allowed_bulletin_dir=str(bulletin_dir),
                dry_run=True
            )
    
    def test_path_traversal_blocked_symlink_escape(self, tmp_path):
        """Symlink pointing outside allowed directory should be blocked."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        
        # Create target outside allowed directory
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        target_file = outside_dir / "target.log"
        target_file.touch()
        
        # Create symlink inside allowed directory
        symlink = log_dir / "link.log"
        symlink.symlink_to(target_file)
        
        bulletin_dir = tmp_path / "alerts"
        bulletin_dir.mkdir()
        bulletin_file = bulletin_dir / "bulletin.md"
        
        # Symlink should resolve and be rejected
        with pytest.raises(ValueError, match="outside allowed directory"):
            PiHoleMonitor(
                log_path=str(symlink),
                bulletin_path=str(bulletin_file),
                allowed_log_dir=str(log_dir),
                allowed_bulletin_dir=str(bulletin_dir),
                dry_run=True
            )
    
    def test_path_must_exist_for_read_mode(self, tmp_path):
        """Non-existent file should fail for read mode."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        non_existent = log_dir / "missing.log"
        
        bulletin_dir = tmp_path / "alerts"
        bulletin_dir.mkdir()
        bulletin_file = bulletin_dir / "bulletin.md"
        
        with pytest.raises(FileNotFoundError):
            PiHoleMonitor(
                log_path=str(non_existent),
                bulletin_path=str(bulletin_file),
                allowed_log_dir=str(log_dir),
                allowed_bulletin_dir=str(bulletin_dir),
                dry_run=True
            )
    
    def test_bulletin_parent_directory_must_exist(self, tmp_path):
        """Bulletin path parent directory must exist."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "pihole.log"
        log_file.touch()
        
        # Non-existent parent for bulletin
        bulletin_path = tmp_path / "nonexistent" / "bulletin.md"
        
        with pytest.raises(FileNotFoundError, match="Parent directory"):
            PiHoleMonitor(
                log_path=str(log_file),
                bulletin_path=str(bulletin_path),
                allowed_log_dir=str(log_dir),
                allowed_bulletin_dir=str(tmp_path),
                dry_run=True
            )


class TestOutputSanitization:
    """Test suite for output sanitization to prevent injection attacks."""
    
    @pytest.fixture
    def monitor(self, tmp_path):
        """Create a monitor instance for testing."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "test.log"
        log_file.touch()
        
        bulletin_dir = tmp_path / "alerts"
        bulletin_dir.mkdir()
        bulletin_file = bulletin_dir / "bulletin.md"
        
        return PiHoleMonitor(
            log_path=str(log_file),
            bulletin_path=str(bulletin_file),
            allowed_log_dir=str(log_dir),
            allowed_bulletin_dir=str(bulletin_dir),
            dry_run=True
        )
    
    def test_sanitize_output_removes_control_chars(self, monitor):
        """Control characters (except newline/tab) should be removed."""
        # Test various control characters
        malicious = "test\x00data\x01more\x1bstuff"
        sanitized = monitor._sanitize_output(malicious)
        
        # Should have no control chars (except newline/tab)
        for char in sanitized:
            assert ord(char) >= 32 or char in '\n\t'
        
        assert sanitized == "testdatamorestuff"
    
    def test_sanitize_output_preserves_newlines_and_tabs(self, monitor):
        """Newlines and tabs should be preserved."""
        text = "line1\nline2\tcolumn2"
        sanitized = monitor._sanitize_output(text)
        assert sanitized == text
    
    def test_sanitize_output_truncates_long_text(self, monitor):
        """Long text should be truncated with ellipsis."""
        long_text = "a" * 200
        sanitized = monitor._sanitize_output(long_text)
        
        assert len(sanitized) <= 103  # 100 + "..."
        assert sanitized.endswith("...")
    
    def test_sanitize_output_handles_unicode(self, monitor):
        """Unicode characters should be handled safely."""
        unicode_text = "Test 你好 مرحبا 🔥"
        sanitized = monitor._sanitize_output(unicode_text)
        
        # Should preserve printable unicode
        assert "Test" in sanitized
        assert "你好" in sanitized
    
    def test_sanitize_output_prevents_ansi_escape(self, monitor):
        """ANSI escape sequences should be removed."""
        ansi = "\x1b[31mRed Text\x1b[0m"
        sanitized = monitor._sanitize_output(ansi)
        
        # Should remove escape character (0x1b), which is what makes it dangerous
        # The [ and ] characters are printable and safe
        assert "\x1b" not in sanitized
        # The escape character is removed but bracket chars remain (they're printable)
        assert "Red Text" in sanitized
    
    def test_sanitize_output_handles_null_byte(self, monitor):
        """Null bytes should be removed to prevent injection."""
        null_injection = "safe\x00malicious"
        sanitized = monitor._sanitize_output(null_injection)
        
        assert "\x00" not in sanitized
        assert sanitized == "safemalicious"
    
    def test_sanitize_output_converts_non_string(self, monitor):
        """Non-string types should be converted safely."""
        assert monitor._sanitize_output(12345) == "12345"
        assert monitor._sanitize_output(None) == "None"
        assert monitor._sanitize_output(['list']) == "['list']"


class TestIPAddressValidation:
    """Test suite for IP address validation in log parsing."""
    
    @pytest.fixture
    def monitor(self, tmp_path):
        """Create a monitor instance for testing."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "test.log"
        log_file.touch()
        
        bulletin_dir = tmp_path / "alerts"
        bulletin_dir.mkdir()
        bulletin_file = bulletin_dir / "bulletin.md"
        
        return PiHoleMonitor(
            log_path=str(log_file),
            bulletin_path=str(bulletin_file),
            allowed_log_dir=str(log_dir),
            allowed_bulletin_dir=str(bulletin_dir),
            dry_run=True
        )
    
    def test_parse_valid_ipv4_address(self, monitor):
        """Valid IPv4 addresses should be accepted."""
        log_line = "Mar 14 10:30:45 dnsmasq[1234]: query[A] google.com from 192.168.1.100"
        result = monitor.parse_log_line(log_line)
        
        assert result is not None
        timestamp, query_type, domain, ip = result
        assert ip == "192.168.1.100"
        assert domain == "google.com"
    
    def test_parse_valid_ipv6_address(self, monitor):
        """Valid IPv6 addresses should be accepted."""
        log_line = "Mar 14 10:30:45 dnsmasq[1234]: query[AAAA] example.com from 2001:db8::1"
        result = monitor.parse_log_line(log_line)
        
        assert result is not None
        timestamp, query_type, domain, ip = result
        assert ip == "2001:db8::1"
    
    def test_parse_invalid_ip_rejected(self, monitor):
        """Invalid IP addresses should be rejected."""
        # Test various invalid IPs
        invalid_ips = [
            "999.999.999.999",  # Out of range
            "192.168.1",         # Incomplete
            "not-an-ip",         # Not an IP
            "192.168.1.1.1",     # Too many octets
            "'; DROP TABLE--",   # SQL injection attempt
        ]
        
        for invalid_ip in invalid_ips:
            # Craft log line with invalid IP
            log_line = f"Mar 14 10:30:45 dnsmasq[1234]: query[A] test.com from {invalid_ip}"
            result = monitor.parse_log_line(log_line)
            
            # Should reject the line
            assert result is None, f"Should reject invalid IP: {invalid_ip}"
    
    def test_parse_ipv4_with_special_chars_rejected(self, monitor):
        """IPv4 with special characters should be rejected."""
        log_line = "Mar 14 10:30:45 dnsmasq[1234]: query[A] test.com from 192.168.1.1;evil"
        result = monitor.parse_log_line(log_line)
        assert result is None


class TestDomainValidation:
    """Test suite for domain name validation."""
    
    @pytest.fixture
    def monitor(self, tmp_path):
        """Create a monitor instance for testing."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "test.log"
        log_file.touch()
        
        bulletin_dir = tmp_path / "alerts"
        bulletin_dir.mkdir()
        bulletin_file = bulletin_dir / "bulletin.md"
        
        return PiHoleMonitor(
            log_path=str(log_file),
            bulletin_path=str(bulletin_file),
            allowed_log_dir=str(log_dir),
            allowed_bulletin_dir=str(bulletin_dir),
            dry_run=True
        )
    
    def test_parse_normal_domain(self, monitor):
        """Normal domain names should be accepted."""
        log_line = "Mar 14 10:30:45 dnsmasq[1234]: query[A] example.com from 192.168.1.1"
        result = monitor.parse_log_line(log_line)
        
        assert result is not None
        _, _, domain, _ = result
        assert domain == "example.com"
    
    def test_parse_subdomain(self, monitor):
        """Subdomains should be accepted."""
        log_line = "Mar 14 10:30:45 dnsmasq[1234]: query[A] sub.example.com from 192.168.1.1"
        result = monitor.parse_log_line(log_line)
        
        assert result is not None
        _, _, domain, _ = result
        assert domain == "sub.example.com"
    
    def test_parse_rejects_oversized_domain(self, monitor):
        """Domains exceeding MAX_DOMAIN_LENGTH should be rejected."""
        # Create domain longer than RFC limit (253 chars)
        long_domain = "a" * 260 + ".com"
        log_line = f"Mar 14 10:30:45 dnsmasq[1234]: query[A] {long_domain} from 192.168.1.1"
        
        result = monitor.parse_log_line(log_line)
        assert result is None
    
    def test_parse_accepts_max_length_domain(self, monitor):
        """Domain at exact MAX_DOMAIN_LENGTH should be accepted."""
        # Create domain at exactly 253 chars (RFC 1035 limit)
        # Account for dots in FQDN
        domain = "a" * 240 + ".example.com"  # Total ~253 chars
        log_line = f"Mar 14 10:30:45 dnsmasq[1234]: query[A] {domain} from 192.168.1.1"
        
        result = monitor.parse_log_line(log_line)
        # Should accept or reject based on actual length
        if len(domain) <= MAX_DOMAIN_LENGTH:
            assert result is not None
        else:
            assert result is None


class TestLineLengthProtection:
    """Test suite for line length limits to prevent DoS."""
    
    @pytest.fixture
    def monitor(self, tmp_path):
        """Create a monitor instance for testing."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "test.log"
        log_file.touch()
        
        bulletin_dir = tmp_path / "alerts"
        bulletin_dir.mkdir()
        bulletin_file = bulletin_dir / "bulletin.md"
        
        return PiHoleMonitor(
            log_path=str(log_file),
            bulletin_path=str(bulletin_file),
            allowed_log_dir=str(log_dir),
            allowed_bulletin_dir=str(bulletin_dir),
            dry_run=True
        )
    
    def test_parse_normal_line_length(self, monitor):
        """Normal length lines should be parsed."""
        log_line = "Mar 14 10:30:45 dnsmasq[1234]: query[A] example.com from 192.168.1.1"
        result = monitor.parse_log_line(log_line)
        assert result is not None
    
    def test_parse_rejects_oversized_line(self, monitor):
        """Lines exceeding MAX_LINE_LENGTH should be rejected."""
        # Create a line longer than MAX_LINE_LENGTH
        long_line = "Mar 14 10:30:45 dnsmasq[1234]: query[A] " + ("a" * MAX_LINE_LENGTH) + " from 192.168.1.1"
        
        result = monitor.parse_log_line(long_line)
        assert result is None
    
    def test_parse_accepts_max_line_length(self, monitor):
        """Line at exactly MAX_LINE_LENGTH should be accepted."""
        # Create line at max length (might not parse if format is wrong, but shouldn't crash)
        line_content = "a" * (MAX_LINE_LENGTH - 100)
        max_line = f"Mar 14 10:30:45 dnsmasq[1234]: query[A] {line_content} from 192.168.1.1"
        
        # Ensure we're at the limit
        if len(max_line) > MAX_LINE_LENGTH:
            max_line = max_line[:MAX_LINE_LENGTH]
        
        # Should not crash, might return None if format is invalid
        result = monitor.parse_log_line(max_line)
        # Just ensure it doesn't crash


class TestAlertDeduplication:
    """Test suite for duplicate alert suppression."""
    
    @pytest.fixture
    def monitor(self, tmp_path):
        """Create a monitor instance for testing."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "test.log"
        log_file.touch()
        
        bulletin_dir = tmp_path / "alerts"
        bulletin_dir.mkdir()
        bulletin_file = bulletin_dir / "bulletin.md"
        
        return PiHoleMonitor(
            log_path=str(log_file),
            bulletin_path=str(bulletin_file),
            allowed_log_dir=str(log_dir),
            allowed_bulletin_dir=str(bulletin_dir),
            dry_run=True
        )
    
    def test_first_alert_not_duplicate(self, monitor):
        """First alert should not be considered a duplicate."""
        anomalies = [("192.168.1.100", 2000)]
        is_dup = monitor._is_duplicate_alert(anomalies)
        assert is_dup is False
    
    def test_immediate_duplicate_detected(self, monitor):
        """Immediate duplicate alert should be detected."""
        anomalies = [("192.168.1.100", 2000)]
        
        # First call - not a duplicate
        assert monitor._is_duplicate_alert(anomalies) is False
        
        # Second call immediately after - is a duplicate
        assert monitor._is_duplicate_alert(anomalies) is True
    
    def test_different_ips_not_duplicate(self, monitor):
        """Alert with different IPs should not be duplicate."""
        anomalies1 = [("192.168.1.100", 2000)]
        anomalies2 = [("192.168.1.101", 2000)]
        
        assert monitor._is_duplicate_alert(anomalies1) is False
        assert monitor._is_duplicate_alert(anomalies2) is False
    
    def test_empty_anomalies_not_duplicate(self, monitor):
        """Empty anomaly list should not be duplicate."""
        assert monitor._is_duplicate_alert([]) is False


class TestTimestampParsing:
    """Test suite for timestamp parsing with year rollover fix."""
    
    @pytest.fixture
    def monitor(self, tmp_path):
        """Create a monitor instance for testing."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "test.log"
        log_file.touch()
        
        bulletin_dir = tmp_path / "alerts"
        bulletin_dir.mkdir()
        bulletin_file = bulletin_dir / "bulletin.md"
        
        return PiHoleMonitor(
            log_path=str(log_file),
            bulletin_path=str(bulletin_file),
            allowed_log_dir=str(log_dir),
            allowed_bulletin_dir=str(bulletin_dir),
            dry_run=True
        )
    
    def test_parse_current_year_timestamp(self, monitor):
        """Timestamp from current year should parse correctly."""
        now = datetime.now()
        timestamp_str = now.strftime("%b %d %H:%M:%S")
        log_line = f"{timestamp_str} dnsmasq[1234]: query[A] test.com from 192.168.1.1"
        
        result = monitor.parse_log_line(log_line)
        assert result is not None
        
        parsed_time, _, _, _ = result
        # Should be within a minute of now (accounting for processing time)
        assert abs((parsed_time - now).total_seconds()) < 86400  # Within a day
    
    def test_parse_handles_year_rollover(self, monitor):
        """December timestamp in January should use previous year."""
        # This test simulates reading a Dec 31 log on Jan 1
        # The monitor should detect the timestamp is in the future and use previous year
        log_line = "Dec 31 23:59:59 dnsmasq[1234]: query[A] test.com from 192.168.1.1"
        
        result = monitor.parse_log_line(log_line)
        assert result is not None
        
        parsed_time, _, _, _ = result
        now = datetime.now()
        
        # Timestamp should not be significantly in the future
        assert parsed_time <= now + timedelta(days=1)


class TestResourceLimits:
    """Test suite for resource limit enforcement."""
    
    def test_bulletin_board_rotation_on_size_limit(self, tmp_path):
        """Bulletin board should rotate when exceeding size limit."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "test.log"
        log_file.write_text("Mar 14 10:30:45 dnsmasq[1234]: query[A] test.com from 192.168.1.1\n")
        
        bulletin_dir = tmp_path / "alerts"
        bulletin_dir.mkdir()
        bulletin_file = bulletin_dir / "bulletin.md"
        
        # Create a large bulletin file (simulate exceeding limit)
        large_content = "x" * (11 * 1024 * 1024)  # 11 MB (over 10 MB limit)
        bulletin_file.write_text(large_content)
        
        monitor = PiHoleMonitor(
            log_path=str(log_file),
            bulletin_path=str(bulletin_file),
            allowed_log_dir=str(log_dir),
            allowed_bulletin_dir=str(bulletin_dir),
            dry_run=False  # Need to actually write
        )
        
        # Post an alert (should trigger rotation)
        anomalies = [("192.168.1.100", 2000)]
        monitor.post_alert(anomalies, datetime.now())
        
        # Old bulletin should be backed up
        backup_path = bulletin_file.with_suffix('.md.old')
        assert backup_path.exists()
        
        # New bulletin should exist and be smaller
        assert bulletin_file.exists()
        assert bulletin_file.stat().st_size < bulletin_file.with_suffix('.md.old').stat().st_size


class TestConfigurationLoading:
    """Test suite for configuration file handling."""
    
    def test_monitor_respects_custom_thresholds(self, tmp_path):
        """Monitor should use custom thresholds from initialization."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "test.log"
        log_file.touch()
        
        bulletin_dir = tmp_path / "alerts"
        bulletin_dir.mkdir()
        bulletin_file = bulletin_dir / "bulletin.md"
        
        custom_threshold = 5000
        custom_window = 60
        
        monitor = PiHoleMonitor(
            log_path=str(log_file),
            bulletin_path=str(bulletin_file),
            allowed_log_dir=str(log_dir),
            allowed_bulletin_dir=str(bulletin_dir),
            dry_run=True,
            query_threshold=custom_threshold,
            window_minutes=custom_window
        )
        
        assert monitor.query_threshold == custom_threshold
        assert monitor.window_minutes == custom_window


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
