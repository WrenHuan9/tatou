"""Comprehensive unit tests for security_monitor.py module.

This test suite provides complete coverage of the SecurityMonitor class including:
- Attack detection algorithms (brute force, rate limiting, file upload, path traversal)
- State management (suspicious IPs, time windows, counters)
- Recovery mechanisms (attack recovery, data cleanup)
- Edge cases and error handling
- Threshold validation and time window logic
"""

import time
import pytest
from unittest.mock import Mock, MagicMock, patch
from collections import deque
from typing import Dict, Any

# Import the module under test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from security_monitor import SecurityMonitor


class TestSecurityMonitor:
    """Test the SecurityMonitor class functionality."""

    def setup_method(self):
        """Set up test fixtures before each test method."""
        self.mock_logger = Mock()
        self.monitor = SecurityMonitor(self.mock_logger)
        
        # Reset time for consistent testing
        self.original_time = time.time
        time.time = Mock(return_value=1000.0)

    def teardown_method(self):
        """Clean up after each test method."""
        time.time = self.original_time

    def test_init_defaults(self):
        """Test SecurityMonitor initialization with default values."""
        monitor = SecurityMonitor()
        
        assert monitor.LOGIN_ATTEMPTS_THRESHOLD == 5
        assert monitor.LOGIN_TIME_WINDOW == 300
        assert monitor.FILE_SIZE_LIMIT == 50 * 1024 * 1024
        assert monitor.REQUEST_RATE_LIMIT == 100
        assert monitor.REQUEST_TIME_WINDOW == 60
        assert len(monitor.suspicious_ips) == 0
        assert len(monitor.login_attempts) == 0
        assert len(monitor.request_counts) == 0

    def test_init_with_logger(self):
        """Test SecurityMonitor initialization with custom logger."""
        custom_logger = Mock()
        monitor = SecurityMonitor(custom_logger)
        assert monitor.logger == custom_logger

    # ==================== LOGIN BRUTE FORCE TESTS ====================

    def test_check_login_brute_force_success_clears_attempts(self):
        """Test that successful login clears previous failed attempts."""
        ip = "192.168.1.1"
        
        # Add some failed attempts first
        self.monitor.login_attempts[ip].append(999.0)
        self.monitor.login_attempts[ip].append(999.5)
        
        # Successful login should clear attempts
        result = self.monitor.check_login_brute_force(ip, True)
        
        assert result is False
        assert ip not in self.monitor.login_attempts
        assert ip not in self.monitor.suspicious_ips

    def test_check_login_brute_force_failed_under_threshold(self):
        """Test failed login under threshold doesn't trigger alert."""
        ip = "192.168.1.1"
        
        # Add 4 failed attempts (under threshold of 5)
        for i in range(4):
            time.time.return_value = 1000.0 + i
            result = self.monitor.check_login_brute_force(ip, False)
            assert result is False
        
        assert ip not in self.monitor.suspicious_ips
        assert len(self.monitor.login_attempts[ip]) == 4

    def test_check_login_brute_force_exceeds_threshold(self):
        """Test failed login exceeding threshold triggers alert."""
        ip = "192.168.1.1"
        
        # Add 5 failed attempts (exceeds threshold)
        for i in range(5):
            time.time.return_value = 1000.0 + i
            result = self.monitor.check_login_brute_force(ip, False)
        
        # Last attempt should trigger alert
        assert result is True
        assert ip in self.monitor.suspicious_ips
        assert len(self.monitor.login_attempts[ip]) == 5
        
        # Verify logging was called (should be called twice: security_alert and attack_incident)
        assert self.mock_logger.warning.call_count == 2
        
        # Check first call (security_alert)
        first_call_args = self.mock_logger.warning.call_args_list[0][0]
        assert "event=security_alert" in first_call_args[0]
        assert "type=brute_force_login" in first_call_args[0]
        assert first_call_args[1] == ip  # ip parameter
        assert first_call_args[2] == 5   # attempts parameter

    def test_check_login_brute_force_time_window_cleanup(self):
        """Test that old login attempts are cleaned up based on time window."""
        ip = "192.168.1.1"
        
        # Add old attempts (outside time window)
        self.monitor.login_attempts[ip].append(1000.0 - 400)  # 400 seconds ago
        self.monitor.login_attempts[ip].append(1000.0 - 350)  # 350 seconds ago
        
        # Add recent attempts
        self.monitor.login_attempts[ip].append(1000.0 - 100)  # 100 seconds ago
        self.monitor.login_attempts[ip].append(1000.0 - 50)   # 50 seconds ago
        
        # Current time is 1000.0, time window is 300 seconds
        time.time.return_value = 1000.0
        result = self.monitor.check_login_brute_force(ip, False)
        
        # Should have 3 attempts: 2 recent + 1 new attempt from this call
        # The cleanup happens before adding the new attempt
        assert len(self.monitor.login_attempts[ip]) == 3
        assert result is False

    # ==================== FILE UPLOAD ATTACK TESTS ====================

    def test_check_file_upload_attack_normal_size(self):
        """Test normal file size doesn't trigger attack detection."""
        ip = "192.168.1.1"
        file_size = 10 * 1024 * 1024  # 10MB
        filename = "normal_file.pdf"
        
        result = self.monitor.check_file_upload_attack(ip, file_size, filename)
        
        assert result is False
        self.mock_logger.warning.assert_not_called()

    def test_check_file_upload_attack_oversized_file(self):
        """Test oversized file triggers attack detection."""
        ip = "192.168.1.1"
        file_size = 60 * 1024 * 1024  # 60MB (exceeds 50MB limit)
        filename = "large_file.pdf"
        
        result = self.monitor.check_file_upload_attack(ip, file_size, filename)
        
        assert result is True
        self.mock_logger.warning.assert_called_once()
        call_args = self.mock_logger.warning.call_args[0]
        assert "event=security_alert" in call_args[0]
        assert "type=large_file_upload" in call_args[0]
        assert call_args[1] == ip  # ip parameter
        assert call_args[2] == file_size  # size parameter
        assert call_args[3] == filename  # filename parameter

    def test_check_file_upload_attack_suspicious_filename(self):
        """Test suspicious filename triggers attack detection."""
        ip = "192.168.1.1"
        file_size = 10 * 1024 * 1024  # 10MB
        suspicious_filenames = [
            "file<>.pdf",
            "file|.pdf", 
            "file:.pdf",
            "file\".pdf",
            "file?.pdf",
            "file*.pdf"
        ]
        
        for filename in suspicious_filenames:
            result = self.monitor.check_file_upload_attack(ip, file_size, filename)
            assert result is True
            self.mock_logger.warning.assert_called()
            call_args = self.mock_logger.warning.call_args[0]
            assert "event=security_alert" in call_args[0]
            assert "type=suspicious_filename" in call_args[0]

    # ==================== PATH TRAVERSAL TESTS ====================

    def test_check_path_traversal_normal_path(self):
        """Test normal path doesn't trigger traversal detection."""
        ip = "192.168.1.1"
        normal_paths = [
            "/api/documents",
            "/static/style.css",
            "/healthz",
            "/api/login"
        ]
        
        for path in normal_paths:
            result = self.monitor.check_path_traversal(ip, path)
            assert result is False

    def test_check_path_traversal_malicious_path(self):
        """Test malicious path triggers traversal detection."""
        ip = "192.168.1.1"
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "//etc/passwd",
            "/api/../../../etc/passwd",
            "/static/../../config.json"
        ]
        
        for path in malicious_paths:
            result = self.monitor.check_path_traversal(ip, path)
            assert result is True
            self.mock_logger.warning.assert_called()
            call_args = self.mock_logger.warning.call_args[0]
            assert "event=security_alert" in call_args[0]
            assert "type=path_traversal" in call_args[0]

    # ==================== RATE LIMITING TESTS ====================

    def test_check_rate_limiting_under_limit(self):
        """Test requests under rate limit don't trigger blocking."""
        ip = "192.168.1.1"
        
        # Make 50 requests (under 100 limit)
        for i in range(50):
            time.time.return_value = 1000.0 + i
            result = self.monitor.check_rate_limiting(ip)
            assert result is False
        
        assert len(self.monitor.request_counts[ip]) == 50

    def test_check_rate_limiting_exceeds_limit(self):
        """Test requests exceeding rate limit trigger blocking."""
        ip = "192.168.1.1"
        
        # Make requests within the time window to exceed the limit
        # We need to make requests that stay within the 60-second window
        result = False
        for i in range(101):
            time.time.return_value = 1000.0 + (i * 0.5)  # 0.5 second intervals
            result = self.monitor.check_rate_limiting(ip)
            if result:  # Stop when we trigger the limit
                break
        
        # Should trigger blocking when count exceeds 100
        assert result is True
        assert ip in self.monitor.suspicious_ips
        self.mock_logger.warning.assert_called()
        call_args = self.mock_logger.warning.call_args[0]
        assert "event=security_alert" in call_args[0]
        assert "type=rate_limit_exceeded" in call_args[0]
        assert call_args[1] == ip  # ip parameter
        assert call_args[2] > 100  # requests parameter should be > 100

    def test_check_rate_limiting_time_window_cleanup(self):
        """Test that old requests are cleaned up based on time window."""
        ip = "192.168.1.1"
        
        # Add old requests (outside time window)
        self.monitor.request_counts[ip].append(1000.0 - 120)  # 120 seconds ago
        self.monitor.request_counts[ip].append(1000.0 - 80)   # 80 seconds ago
        
        # Add recent requests
        self.monitor.request_counts[ip].append(1000.0 - 30)   # 30 seconds ago
        self.monitor.request_counts[ip].append(1000.0 - 10)   # 10 seconds ago
        
        # Current time is 1000.0, time window is 60 seconds
        time.time.return_value = 1000.0
        result = self.monitor.check_rate_limiting(ip)
        
        # Should have 3 requests: 2 recent + 1 new request from this call
        # The cleanup happens before adding the new request
        assert len(self.monitor.request_counts[ip]) == 3
        assert result is False

    # ==================== WATERMARK BRUTE FORCE TESTS ====================

    def test_check_watermark_link_brute_force_normal_404(self):
        """Test normal 404 responses don't trigger brute force detection."""
        ip = "192.168.1.1"
        
        # Make 10 404 requests (under 20 threshold)
        for i in range(10):
            time.time.return_value = 1000.0 + i
            result = self.monitor.check_watermark_link_brute_force(ip, 404)
            assert result is False
        
        assert ip not in self.monitor.suspicious_ips

    def test_check_watermark_link_brute_force_exceeds_threshold(self):
        """Test 404 responses exceeding threshold trigger brute force detection."""
        ip = "192.168.1.1"
        
        # Make 21 404 requests (exceeds 20 threshold)
        for i in range(21):
            time.time.return_value = 1000.0 + i
            result = self.monitor.check_watermark_link_brute_force(ip, 404)
        
        # Last request should trigger detection
        assert result is True
        assert ip in self.monitor.suspicious_ips
        self.mock_logger.warning.assert_called()
        call_args = self.mock_logger.warning.call_args[0]
        assert "event=security_alert" in call_args[0]
        assert "type=watermark_brute_force" in call_args[0]

    def test_check_watermark_link_brute_force_non_404_status(self):
        """Test non-404 status codes don't trigger brute force detection."""
        ip = "192.168.1.1"
        status_codes = [200, 201, 400, 401, 403, 500]
        
        for status_code in status_codes:
            result = self.monitor.check_watermark_link_brute_force(ip, status_code)
            assert result is False

    # ==================== RMAP ATTACK TESTS ====================

    def test_check_rmap_attack_success(self):
        """Test successful RMAP operations don't trigger attack detection."""
        ip = "192.168.1.1"
        
        result = self.monitor.check_rmap_attack(ip, True)
        assert result is False
        self.mock_logger.warning.assert_not_called()

    def test_check_rmap_attack_failure(self):
        """Test failed RMAP operations trigger attack detection."""
        ip = "192.168.1.1"
        error_msg = "decryption failed"
        
        result = self.monitor.check_rmap_attack(ip, False, error_msg)
        assert result is True
        self.mock_logger.warning.assert_called_once()
        call_args = self.mock_logger.warning.call_args[0]
        assert "event=security_alert" in call_args[0]
        assert "type=rmap_attack" in call_args[0]
        assert call_args[1] == ip  # ip parameter
        assert call_args[2] == error_msg  # error parameter

    # ==================== ADMIN ACCESS ATTACK TESTS ====================

    def test_check_admin_access_attack_success(self):
        """Test successful admin access doesn't trigger attack detection."""
        ip = "192.168.1.1"
        
        result = self.monitor.check_admin_access_attack(ip, True)
        assert result is False
        self.mock_logger.warning.assert_not_called()

    def test_check_admin_access_attack_failure(self):
        """Test failed admin access triggers attack detection."""
        ip = "192.168.1.1"
        
        result = self.monitor.check_admin_access_attack(ip, False)
        assert result is True
        self.mock_logger.warning.assert_called_once()
        call_args = self.mock_logger.warning.call_args[0]
        assert "event=security_alert" in call_args[0]
        assert "type=admin_access_attack" in call_args[0]
        assert call_args[1] == ip  # ip parameter

    # ==================== SUSPICIOUS IP TESTS ====================

    def test_is_suspicious_ip_true(self):
        """Test IP marked as suspicious returns True."""
        ip = "192.168.1.1"
        self.monitor.suspicious_ips.add(ip)
        
        assert self.monitor.is_suspicious_ip(ip) is True

    def test_is_suspicious_ip_false(self):
        """Test IP not marked as suspicious returns False."""
        ip = "192.168.1.1"
        
        assert self.monitor.is_suspicious_ip(ip) is False

    # ==================== SECURITY SUMMARY TESTS ====================

    def test_get_security_summary_empty(self):
        """Test security summary with no activity."""
        summary = self.monitor.get_security_summary()
        
        assert summary["suspicious_ips"] == []
        assert summary["active_login_attempts"] == {}
        assert summary["active_request_counts"] == {}

    def test_get_security_summary_with_activity(self):
        """Test security summary with active monitoring data."""
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"
        
        # Add some activity
        self.monitor.suspicious_ips.add(ip1)
        self.monitor.login_attempts[ip1].append(1000.0)
        self.monitor.login_attempts[ip1].append(1000.1)
        self.monitor.request_counts[ip2].append(1000.0)
        
        summary = self.monitor.get_security_summary()
        
        assert ip1 in summary["suspicious_ips"]
        assert summary["active_login_attempts"][ip1] == 2
        assert summary["active_request_counts"][ip2] == 1

    # ==================== RECOVERY MECHANISM TESTS ====================

    def test_recover_from_attack_specific_ip(self):
        """Test recovery for a specific IP."""
        ip = "192.168.1.1"
        
        # Set up attack state
        self.monitor.suspicious_ips.add(ip)
        self.monitor.login_attempts[ip].append(1000.0)
        self.monitor.request_counts[ip].append(1000.0)
        
        # Recover specific IP
        result = self.monitor.recover_from_attack(ip=ip)
        
        assert ip not in self.monitor.suspicious_ips
        assert ip not in self.monitor.login_attempts
        assert ip not in self.monitor.request_counts
        assert len(result["recovery_actions"]) == 3
        assert "Removed IP" in result["recovery_actions"][0]
        assert result["remaining_suspicious_ips"] == 0

    def test_recover_from_attack_brute_force_type(self):
        """Test recovery for brute force attack type."""
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"
        
        # Set up brute force attempts
        self.monitor.login_attempts[ip1].append(1000.0)
        self.monitor.login_attempts[ip2].append(1000.0)
        self.monitor.request_counts[ip1].append(1000.0)  # Should remain
        
        # Recover brute force attacks
        result = self.monitor.recover_from_attack(attack_type="brute_force")
        
        assert len(self.monitor.login_attempts) == 0
        assert len(self.monitor.request_counts) == 1  # Should remain
        assert "Cleared all brute force attempts" in result["recovery_actions"]

    def test_recover_from_attack_rate_limit_type(self):
        """Test recovery for rate limit attack type."""
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"
        
        # Set up rate limit attempts
        self.monitor.request_counts[ip1].append(1000.0)
        self.monitor.request_counts[ip2].append(1000.0)
        self.monitor.login_attempts[ip1].append(1000.0)  # Should remain
        
        # Recover rate limit attacks
        result = self.monitor.recover_from_attack(attack_type="rate_limit")
        
        assert len(self.monitor.request_counts) == 0
        assert len(self.monitor.login_attempts) == 1  # Should remain
        assert "Cleared all rate limit counters" in result["recovery_actions"]

    def test_recover_from_attack_all_type(self):
        """Test recovery for all attack types."""
        ip = "192.168.1.1"
        
        # Set up all types of attacks
        self.monitor.suspicious_ips.add(ip)
        self.monitor.login_attempts[ip].append(1000.0)
        self.monitor.request_counts[ip].append(1000.0)
        
        # Recover all attacks
        result = self.monitor.recover_from_attack(attack_type="all")
        
        assert len(self.monitor.suspicious_ips) == 0
        assert len(self.monitor.login_attempts) == 0
        assert len(self.monitor.request_counts) == 0
        assert "Cleared all security data" in result["recovery_actions"]

    def test_recover_from_attack_no_parameters(self):
        """Test recovery with no parameters clears everything."""
        ip = "192.168.1.1"
        
        # Set up attack state
        self.monitor.suspicious_ips.add(ip)
        self.monitor.login_attempts[ip].append(1000.0)
        self.monitor.request_counts[ip].append(1000.0)
        
        # Recover without parameters
        result = self.monitor.recover_from_attack()
        
        assert len(self.monitor.suspicious_ips) == 0
        assert len(self.monitor.login_attempts) == 0
        assert len(self.monitor.request_counts) == 0
        assert "Cleared all security data" in result["recovery_actions"]

    # ==================== ATTACK INCIDENT LOGGING TESTS ====================

    def test_log_attack_incident(self):
        """Test attack incident logging functionality."""
        attack_type = "brute_force_login"
        ip = "192.168.1.1"
        details = {"attempts": 5, "threshold": 5}
        
        self.monitor.log_attack_incident(attack_type, ip, details)
        
        # Verify incident was logged
        self.mock_logger.warning.assert_called()
        call_args = self.mock_logger.warning.call_args[0]
        assert "event=attack_incident" in call_args[0]
        assert call_args[1] == attack_type  # type parameter
        assert call_args[2] == ip  # ip parameter
        assert call_args[3] == str(details)  # details parameter
        
        # Verify incident was stored
        incidents = self.monitor.get_attack_incidents()
        assert len(incidents) == 1
        assert incidents[0]["attack_type"] == attack_type
        assert incidents[0]["ip"] == ip
        assert incidents[0]["details"] == details

    def test_get_attack_incidents_limit(self):
        """Test getting attack incidents with limit."""
        # Add multiple incidents
        for i in range(10):
            self.monitor.log_attack_incident("test_attack", f"192.168.1.{i}", {"test": "data"})
        
        # Get limited incidents
        incidents = self.monitor.get_attack_incidents(limit=5)
        assert len(incidents) == 5
        
        # Get all incidents
        all_incidents = self.monitor.get_attack_incidents()
        assert len(all_incidents) == 10

    # ==================== ATTACK PATTERN ANALYSIS TESTS ====================

    def test_analyze_attack_patterns_no_incidents(self):
        """Test attack pattern analysis with no incidents."""
        result = self.monitor.analyze_attack_patterns()
        assert result["analysis"] == "No incidents recorded"

    def test_analyze_attack_patterns_with_incidents(self):
        """Test attack pattern analysis with incidents."""
        # Add various incidents
        self.monitor.log_attack_incident("brute_force_login", "192.168.1.1", {})
        self.monitor.log_attack_incident("brute_force_login", "192.168.1.1", {})
        self.monitor.log_attack_incident("rate_limit_exceeded", "192.168.1.2", {})
        self.monitor.log_attack_incident("path_traversal", "192.168.1.3", {})
        
        result = self.monitor.analyze_attack_patterns()
        
        assert result["total_incidents"] == 4
        assert result["attack_type_distribution"]["brute_force_login"] == 2
        assert result["attack_type_distribution"]["rate_limit_exceeded"] == 1
        assert result["attack_type_distribution"]["path_traversal"] == 1
        assert len(result["top_attacking_ips"]) == 3
        assert result["top_attacking_ips"][0][0] == "192.168.1.1"  # Most frequent
        assert result["top_attacking_ips"][0][1] == 2

    def test_generate_recovery_recommendations(self):
        """Test recovery recommendation generation."""
        # Test with high brute force attacks
        attack_types = {"brute_force_login": 15}
        ip_frequency = {"192.168.1.1": 10, "192.168.1.2": 5}
        
        recommendations = self.monitor._generate_recovery_recommendations(attack_types, ip_frequency)
        assert "CAPTCHA" in recommendations[0]
        
        # Test with high rate limit attacks
        attack_types = {"rate_limit_exceeded": 10}
        recommendations = self.monitor._generate_recovery_recommendations(attack_types, {})
        assert "rate limit thresholds" in recommendations[0]
        
        # Test with many IPs
        ip_frequency = {f"192.168.1.{i}": 1 for i in range(25)}
        recommendations = self.monitor._generate_recovery_recommendations({}, ip_frequency)
        assert "whitelist/blacklist" in recommendations[0]
        
        # Test with no specific patterns
        recommendations = self.monitor._generate_recovery_recommendations({}, {})
        assert "adequate" in recommendations[0]

    # ==================== EDGE CASES AND ERROR HANDLING ====================

    def test_empty_ip_string(self):
        """Test handling of empty IP string."""
        result = self.monitor.check_login_brute_force("", False)
        assert result is False
        
        result = self.monitor.check_rate_limiting("")
        assert result is False

    def test_none_values(self):
        """Test handling of None values."""
        # The current implementation doesn't raise exceptions for None values
        # It just processes them normally, which might not be ideal but is current behavior
        result = self.monitor.check_login_brute_force(None, False)
        assert result is False  # Should not trigger attack detection

    def test_negative_file_size(self):
        """Test handling of negative file size."""
        result = self.monitor.check_file_upload_attack("192.168.1.1", -1000, "test.pdf")
        assert result is False

    def test_very_large_file_size(self):
        """Test handling of very large file size."""
        huge_size = 1000 * 1024 * 1024 * 1024  # 1TB
        result = self.monitor.check_file_upload_attack("192.168.1.1", huge_size, "huge.pdf")
        assert result is True

    def test_unicode_filename(self):
        """Test handling of unicode filenames."""
        unicode_filename = "测试文件.pdf"
        result = self.monitor.check_file_upload_attack("192.168.1.1", 1000, unicode_filename)
        assert result is False  # Should not trigger attack detection

    def test_very_long_path(self):
        """Test handling of very long paths."""
        long_path = "/" + "a" * 10000
        result = self.monitor.check_path_traversal("192.168.1.1", long_path)
        assert result is False  # Should not trigger attack detection

    # ==================== CONCURRENT ACCESS TESTS ====================

    def test_concurrent_ip_access(self):
        """Test concurrent access to same IP from different contexts."""
        ip = "192.168.1.1"
        
        # Simulate concurrent access
        for i in range(10):
            time.time.return_value = 1000.0 + i
            self.monitor.check_rate_limiting(ip)
            self.monitor.check_login_brute_force(ip, False)
        
        # Should handle concurrent access gracefully
        assert len(self.monitor.request_counts[ip]) == 10
        assert len(self.monitor.login_attempts[ip]) == 10
