"""Comprehensive unit tests for security.py module.

This test suite provides complete coverage of the TatouSecurity class including:
- Health check functionality
- Security status monitoring
- Log analysis capabilities
- Attack testing and simulation
- Monitoring cycles and metrics
- Recovery operations
- Command line interface
- Error handling and edge cases
"""

import json
import time
import pytest
from unittest.mock import Mock, MagicMock, patch, mock_open
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

# Import the module under test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from security import TatouSecurity


class TestTatouSecurity:
    """Test the TatouSecurity class functionality."""

    def setup_method(self):
        """Set up test fixtures before each test method."""
        self.base_url = "http://localhost:5000"
        self.admin_key = "test-admin-key"
        self.security = TatouSecurity(self.base_url, self.admin_key)
        
        # Mock the session and logger
        self.security.session = Mock()
        self.security.logger = Mock()

    def teardown_method(self):
        """Clean up after each test method."""
        pass

    def test_init_defaults(self):
        """Test TatouSecurity initialization with default values."""
        security = TatouSecurity()
        
        assert security.base_url == "http://localhost:5000"
        assert security.admin_key == "your-strong-admin-key-for-leak-detection"
        assert security.session is not None
        assert security.logger is not None
        assert security.metrics["health_checks"] == 0
        assert security.metrics["security_alerts"] == 0
        assert security.metrics["failed_requests"] == 0
        assert security.metrics["last_check"] is None

    def test_init_custom_values(self):
        """Test TatouSecurity initialization with custom values."""
        custom_url = "http://test-server:8080"
        custom_key = "custom-admin-key"
        security = TatouSecurity(custom_url, custom_key)
        
        assert security.base_url == custom_url
        assert security.admin_key == custom_key

    # ==================== HEALTH CHECK TESTS ====================

    @patch('security.requests.get')
    def test_check_health_success(self, mock_get):
        """Test successful health check."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        result = self.security.check_health()
        
        assert result is True
        assert self.security.metrics["health_checks"] == 1
        mock_get.assert_called_once_with(f"{self.base_url}/healthz", timeout=5)

    @patch('security.requests.get')
    def test_check_health_failure(self, mock_get):
        """Test failed health check."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        result = self.security.check_health()
        
        assert result is False
        assert self.security.metrics["health_checks"] == 0
        self.security.logger.warning.assert_called()

    @patch('security.requests.get')
    def test_check_health_exception(self, mock_get):
        """Test health check with exception."""
        mock_get.side_effect = Exception("Connection failed")
        
        result = self.security.check_health()
        
        assert result is False
        assert self.security.metrics["failed_requests"] == 1
        self.security.logger.error.assert_called()

    # ==================== SECURITY STATUS TESTS ====================

    @patch('security.requests.get')
    def test_check_security_status_success(self, mock_get):
        """Test successful security status check."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "security_summary": {
                "suspicious_ips": ["192.168.1.1", "192.168.1.2"],
                "active_login_attempts": {"192.168.1.1": 3},
                "active_request_counts": {"192.168.1.2": 5}
            }
        }
        mock_get.return_value = mock_response
        
        result = self.security.check_security_status()
        
        assert result is True
        mock_get.assert_called_once_with(
            f"{self.base_url}/api/security-status",
            headers={'X-Admin-Key': self.admin_key},
            timeout=5
        )

    @patch('security.requests.get')
    def test_check_security_status_failure(self, mock_get):
        """Test failed security status check."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response
        
        result = self.security.check_security_status()
        
        assert result is False

    @patch('security.requests.get')
    def test_check_security_status_exception(self, mock_get):
        """Test security status check with exception."""
        mock_get.side_effect = Exception("Connection failed")
        
        result = self.security.check_security_status()
        
        assert result is False

    # ==================== LOG ANALYSIS TESTS ====================

    def test_analyze_logs_file_not_exists(self):
        """Test log analysis with non-existent file."""
        result = self.security.analyze_logs("non_existent.log")
        
        assert result == {}

    @patch('builtins.open', new_callable=mock_open)
    @patch('security.Path')
    def test_analyze_logs_with_security_events(self, mock_path, mock_file):
        """Test log analysis with security events."""
        mock_path.return_value.exists.return_value = True
        
        # Create a mock file object that can be iterated
        mock_file_obj = MagicMock()
        mock_file_obj.__enter__.return_value = mock_file_obj
        mock_file_obj.__exit__.return_value = None
        mock_file_obj.__iter__.return_value = iter([
            "2023-01-01 10:00:00 INFO event=security_alert type=brute_force_login ip=192.168.1.1",
            "2023-01-01 10:01:00 INFO event=normal_request",
            "2023-01-01 10:02:00 INFO SECURITY_BLOCK: Rate limit exceeded",
            "2023-01-01 10:03:00 INFO event=security_alert type=path_traversal ip=192.168.1.2"
        ])
        mock_file.return_value = mock_file_obj
        
        result = self.security.analyze_logs()
        
        assert result["total_security_events"] == 3
        assert len(result["recent_events"]) == 3
        assert "brute_force_login" in result["recent_events"][0]
        assert "SECURITY_BLOCK" in result["recent_events"][1]
        assert "path_traversal" in result["recent_events"][2]

    @patch('builtins.open', new_callable=mock_open)
    @patch('security.Path')
    def test_analyze_logs_no_security_events(self, mock_path, mock_file):
        """Test log analysis with no security events."""
        mock_path.return_value.exists.return_value = True
        mock_file.return_value.__enter__.return_value.readlines.return_value = [
            "2023-01-01 10:00:00 INFO event=normal_request",
            "2023-01-01 10:01:00 INFO event=login_success",
            "2023-01-01 10:02:00 INFO event=api_request"
        ]
        
        result = self.security.analyze_logs()
        
        assert result["total_security_events"] == 0
        assert result["recent_events"] == []

    # ==================== ATTACK TESTING TESTS ====================

    @patch('security.time.sleep')
    @patch('security.requests.Session')
    def test_run_attack_test_brute_force(self, mock_session_class, mock_sleep):
        """Test brute force attack simulation."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_response = Mock()
        mock_response.status_code = 401
        mock_session.post.return_value = mock_response
        
        # Replace the session with our mock
        self.security.session = mock_session
        
        self.security.run_attack_test()
        
        # Should make 6 login attempts (exceeds threshold of 5)
        assert mock_session.post.call_count == 6
        mock_session.post.assert_called_with(
            f"{self.base_url}/api/login",
            json={"email": "test@example.com", "password": "wrong"}
        )

    @patch('security.time.sleep')
    @patch('security.requests.Session')
    def test_run_attack_test_path_traversal(self, mock_session_class, mock_sleep):
        """Test path traversal attack simulation."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_response = Mock()
        mock_response.status_code = 400
        mock_session.get.return_value = mock_response
        mock_session.post.return_value = mock_response
        
        self.security.session = mock_session
        
        self.security.run_attack_test()
        
        # Should attempt path traversal (check if any call was made to the path traversal URL)
        path_traversal_calls = [call for call in mock_session.get.call_args_list 
                               if len(call[0]) > 0 and '/../../../etc/passwd' in call[0][0]]
        assert len(path_traversal_calls) > 0

    @patch('security.time.sleep')
    @patch('security.requests.Session')
    @patch('security.random.choices')
    def test_run_attack_test_watermark_brute_force(self, mock_choices, mock_session_class, mock_sleep):
        """Test watermark link brute force simulation."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response
        
        # Mock random string generation
        mock_choices.return_value = ['a'] * 32
        
        self.security.session = mock_session
        
        self.security.run_attack_test()
        
        # Should make 25 watermark link attempts (exceeds threshold of 20)
        assert mock_session.get.call_count >= 25

    @patch('security.time.sleep')
    @patch('security.requests.Session')
    def test_run_attack_test_rate_limiting(self, mock_session_class, mock_sleep):
        """Test rate limiting attack simulation."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response
        
        self.security.session = mock_session
        
        self.security.run_attack_test()
        
        # Should make 10 rapid requests
        assert mock_session.get.call_count >= 10

    @patch('security.time.sleep')
    @patch('security.requests.Session')
    def test_run_attack_test_admin_interface(self, mock_session_class, mock_sleep):
        """Test admin interface attack simulation."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_response = Mock()
        mock_response.status_code = 401
        mock_session.get.return_value = mock_response
        
        self.security.session = mock_session
        
        self.security.run_attack_test()
        
        # Should test 3 wrong admin keys
        admin_calls = [call for call in mock_session.get.call_args_list 
                      if '/api/security-status' in call[0][0]]
        assert len(admin_calls) == 3

    # ==================== ALERT GENERATION TESTS ====================

    def test_generate_alert(self):
        """Test security alert generation."""
        self.security.generate_alert("TEST_ALERT", "Test message", "HIGH")
        
        assert self.security.metrics["security_alerts"] == 1
        self.security.logger.warning.assert_called()
        call_args = self.security.logger.warning.call_args[0]
        assert "SECURITY_ALERT: TEST_ALERT - Test message" in call_args[0]

    def test_generate_alert_default_severity(self):
        """Test security alert generation with default severity."""
        self.security.generate_alert("TEST_ALERT", "Test message")
        
        assert self.security.metrics["security_alerts"] == 1
        self.security.logger.warning.assert_called()

    # ==================== SECURITY THRESHOLD TESTS ====================

    def test_check_security_thresholds_no_data(self):
        """Test security threshold check with no data."""
        self.security.check_security_thresholds({})
        # Should not generate any alerts
        assert self.security.metrics["security_alerts"] == 0

    def test_check_security_thresholds_high_suspicious_ips(self):
        """Test security threshold check with high suspicious IP count."""
        security_data = {
            "security_summary": {
                "suspicious_ips": [f"192.168.1.{i}" for i in range(10)]  # 10 IPs > 5 threshold
            }
        }
        
        self.security.check_security_thresholds(security_data)
        
        assert self.security.metrics["security_alerts"] == 1
        self.security.logger.warning.assert_called()
        call_args = self.security.logger.warning.call_args[0]
        assert "SUSPICIOUS_IPS_HIGH" in call_args[0]

    def test_check_security_thresholds_active_brute_force(self):
        """Test security threshold check with active brute force."""
        security_data = {
            "security_summary": {
                "active_login_attempts": {
                    "192.168.1.1": 5,  # > 3 threshold
                    "192.168.1.2": 2   # < 3 threshold
                }
            }
        }
        
        self.security.check_security_thresholds(security_data)
        
        assert self.security.metrics["security_alerts"] == 1
        self.security.logger.warning.assert_called()
        call_args = self.security.logger.warning.call_args[0]
        assert "BRUTE_FORCE_ACTIVE" in call_args[0]

    # ==================== MONITORING CYCLE TESTS ====================

    @patch.object(TatouSecurity, 'check_health')
    @patch.object(TatouSecurity, 'check_security_status')
    @patch.object(TatouSecurity, 'analyze_logs')
    def test_run_monitoring_cycle_healthy(self, mock_analyze_logs, mock_check_security, mock_check_health):
        """Test monitoring cycle with healthy service."""
        mock_check_health.return_value = True
        mock_check_security.return_value = {"security_summary": {"suspicious_ips": []}}
        mock_analyze_logs.return_value = {"total_security_events": 5}
        
        self.security.run_monitoring_cycle()
        
        mock_check_health.assert_called_once()
        mock_check_security.assert_called_once()
        mock_analyze_logs.assert_called_once()
        assert self.security.metrics["last_check"] is not None

    @patch.object(TatouSecurity, 'check_health')
    @patch.object(TatouSecurity, 'check_security_status')
    @patch.object(TatouSecurity, 'analyze_logs')
    def test_run_monitoring_cycle_unhealthy(self, mock_analyze_logs, mock_check_security, mock_check_health):
        """Test monitoring cycle with unhealthy service."""
        mock_check_health.return_value = False
        mock_check_security.return_value = None
        mock_analyze_logs.return_value = {"total_security_events": 5}
        
        self.security.run_monitoring_cycle()
        
        # Should generate service down alert
        assert self.security.metrics["security_alerts"] == 1
        self.security.logger.warning.assert_called()
        call_args = self.security.logger.warning.call_args[0]
        assert "SERVICE_DOWN" in call_args[0]

    @patch.object(TatouSecurity, 'check_health')
    @patch.object(TatouSecurity, 'check_security_status')
    @patch.object(TatouSecurity, 'analyze_logs')
    def test_run_monitoring_cycle_high_security_events(self, mock_analyze_logs, mock_check_security, mock_check_health):
        """Test monitoring cycle with high security events."""
        mock_check_health.return_value = True
        mock_check_security.return_value = {"security_summary": {"suspicious_ips": []}}
        mock_analyze_logs.return_value = {"total_security_events": 15}  # > 10 threshold
        
        self.security.run_monitoring_cycle()
        
        # Should generate high security events alert
        assert self.security.metrics["security_alerts"] == 1
        self.security.logger.warning.assert_called()
        call_args = self.security.logger.warning.call_args[0]
        assert "HIGH_SECURITY_EVENTS" in call_args[0]

    # ==================== CONTINUOUS MONITORING TESTS ====================

    @patch('security.time.sleep')
    @patch.object(TatouSecurity, 'run_monitoring_cycle')
    def test_start_monitoring_keyboard_interrupt(self, mock_run_cycle, mock_sleep):
        """Test monitoring with keyboard interrupt."""
        mock_run_cycle.side_effect = KeyboardInterrupt()
        
        self.security.start_monitoring(interval=1)
        
        mock_run_cycle.assert_called_once()
        self.security.logger.info.assert_called()
        call_args = self.security.logger.info.call_args[0]
        assert "Monitoring stopped" in call_args[0]

    @patch('security.time.sleep')
    @patch.object(TatouSecurity, 'run_monitoring_cycle')
    def test_start_monitoring_exception(self, mock_run_cycle, mock_sleep):
        """Test monitoring with exception."""
        mock_run_cycle.side_effect = Exception("Monitoring error")
        
        self.security.start_monitoring(interval=1)
        
        mock_run_cycle.assert_called_once()
        self.security.logger.error.assert_called()
        call_args = self.security.logger.error.call_args[0]
        assert "Monitoring error" in call_args[0]

    # ==================== METRICS TESTS ====================

    def test_get_metrics(self):
        """Test metrics retrieval."""
        self.security.metrics["health_checks"] = 10
        self.security.metrics["security_alerts"] = 5
        self.security.metrics["failed_requests"] = 2
        
        metrics = self.security.get_metrics()
        
        assert metrics["metrics"]["health_checks"] == 10
        assert metrics["metrics"]["security_alerts"] == 5
        assert metrics["metrics"]["failed_requests"] == 2
        assert "timestamp" in metrics

    # ==================== RECOVERY OPERATIONS TESTS ====================

    @patch('security.requests.post')
    def test_recover_from_attacks_success(self, mock_post):
        """Test successful attack recovery."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "recovery_result": {
                "recovery_actions": ["Removed IP 192.168.1.1", "Cleared login attempts"],
                "remaining_suspicious_ips": 0
            }
        }
        mock_post.return_value = mock_response
        
        result = self.security.recover_from_attacks(ip="192.168.1.1")
        
        assert result is True
        mock_post.assert_called_once_with(
            f"{self.base_url}/api/security-recover",
            json={"ip": "192.168.1.1"},
            headers={'X-Admin-Key': self.admin_key, 'Content-Type': 'application/json'},
            timeout=5
        )

    @patch('security.requests.post')
    def test_recover_from_attacks_failure(self, mock_post):
        """Test failed attack recovery."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response
        
        result = self.security.recover_from_attacks(attack_type="all")
        
        assert result is False

    @patch('security.requests.post')
    def test_recover_from_attacks_exception(self, mock_post):
        """Test attack recovery with exception."""
        mock_post.side_effect = Exception("Connection failed")
        
        result = self.security.recover_from_attacks()
        
        assert result is False

    # ==================== INCIDENT RETRIEVAL TESTS ====================

    @patch('security.requests.get')
    def test_get_attack_incidents_success(self, mock_get):
        """Test successful incident retrieval."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "incidents": [
                {
                    "attack_type": "brute_force_login",
                    "ip": "192.168.1.1",
                    "timestamp": 1000000000,
                    "details": {"attempts": 5}
                }
            ]
        }
        mock_get.return_value = mock_response
        
        result = self.security.get_attack_incidents()
        
        assert "incidents" in result
        assert len(result["incidents"]) == 1
        assert result["incidents"][0]["attack_type"] == "brute_force_login"

    @patch('security.requests.get')
    def test_get_attack_incidents_failure(self, mock_get):
        """Test failed incident retrieval."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        result = self.security.get_attack_incidents()
        
        assert result == {}

    # ==================== ATTACK ANALYSIS TESTS ====================

    @patch('security.requests.get')
    def test_analyze_attacks_success(self, mock_get):
        """Test successful attack analysis."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "analysis": {
                "total_incidents": 10,
                "attack_type_distribution": {
                    "brute_force_login": 5,
                    "rate_limit_exceeded": 3,
                    "path_traversal": 2
                },
                "top_attacking_ips": [("192.168.1.1", 5), ("192.168.1.2", 3)],
                "recommendations": ["Implement CAPTCHA", "Reduce rate limits"]
            }
        }
        mock_get.return_value = mock_response
        
        result = self.security.analyze_attacks()
        
        assert "analysis" in result
        assert result["analysis"]["total_incidents"] == 10
        assert result["analysis"]["attack_type_distribution"]["brute_force_login"] == 5

    @patch('security.requests.get')
    def test_analyze_attacks_failure(self, mock_get):
        """Test failed attack analysis."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response
        
        result = self.security.analyze_attacks()
        
        assert result == {}

    # ==================== COMMAND LINE INTERFACE TESTS ====================

    @patch('security.TatouSecurity')
    @patch('sys.argv', ['security.py', 'status'])
    def test_main_status_command(self, mock_security_class):
        """Test main function with status command."""
        mock_security = Mock()
        mock_security_class.return_value = mock_security
        
        from security import main
        main()
        
        mock_security.check_security_status.assert_called_once()

    @patch('security.TatouSecurity')
    @patch('sys.argv', ['security.py', 'logs'])
    def test_main_logs_command(self, mock_security_class):
        """Test main function with logs command."""
        mock_security = Mock()
        mock_security_class.return_value = mock_security
        
        from security import main
        main()
        
        mock_security.analyze_logs.assert_called_once()

    @patch('security.TatouSecurity')
    @patch('sys.argv', ['security.py', 'test'])
    def test_main_test_command(self, mock_security_class):
        """Test main function with test command."""
        mock_security = Mock()
        mock_security_class.return_value = mock_security
        
        from security import main
        main()
        
        mock_security.run_attack_test.assert_called_once()

    @patch('security.TatouSecurity')
    @patch('sys.argv', ['security.py', 'monitor', '--interval', '30'])
    def test_main_monitor_command(self, mock_security_class):
        """Test main function with monitor command."""
        mock_security = Mock()
        mock_security_class.return_value = mock_security
        
        from security import main
        main()
        
        mock_security.start_monitoring.assert_called_once_with(30)

    @patch('security.TatouSecurity')
    @patch('sys.argv', ['security.py', 'recover', '--ip', '192.168.1.1'])
    def test_main_recover_command(self, mock_security_class):
        """Test main function with recover command."""
        mock_security = Mock()
        mock_security_class.return_value = mock_security
        
        from security import main
        main()
        
        mock_security.recover_from_attacks.assert_called_once_with("192.168.1.1", None)

    @patch('security.TatouSecurity')
    @patch('sys.argv', ['security.py', 'recover', '--attack-type', 'all'])
    def test_main_recover_attack_type_command(self, mock_security_class):
        """Test main function with recover attack-type command."""
        mock_security = Mock()
        mock_security_class.return_value = mock_security
        
        from security import main
        main()
        
        mock_security.recover_from_attacks.assert_called_once_with(None, "all")

    @patch('security.TatouSecurity')
    @patch('sys.argv', ['security.py', 'incidents'])
    def test_main_incidents_command(self, mock_security_class):
        """Test main function with incidents command."""
        mock_security = Mock()
        mock_security_class.return_value = mock_security
        
        from security import main
        main()
        
        mock_security.get_attack_incidents.assert_called_once()

    @patch('security.TatouSecurity')
    @patch('sys.argv', ['security.py', 'analyze'])
    def test_main_analyze_command(self, mock_security_class):
        """Test main function with analyze command."""
        mock_security = Mock()
        mock_security_class.return_value = mock_security
        
        from security import main
        main()
        
        mock_security.analyze_attacks.assert_called_once()

    @patch('security.TatouSecurity')
    @patch('sys.argv', ['security.py', 'health'])
    def test_main_health_command(self, mock_security_class):
        """Test main function with health command."""
        mock_security = Mock()
        mock_security_class.return_value = mock_security
        
        from security import main
        main()
        
        mock_security.check_health.assert_called_once()

    @patch('security.TatouSecurity')
    @patch('sys.argv', ['security.py'])
    def test_main_no_command(self, mock_security_class):
        """Test main function with no command (should show help)."""
        mock_security = Mock()
        mock_security_class.return_value = mock_security
        
        from security import main
        main()
        
        # Should not call any security methods
        mock_security.check_health.assert_not_called()
        mock_security.check_security_status.assert_not_called()

    # ==================== EDGE CASES AND ERROR HANDLING ====================

    def test_empty_base_url(self):
        """Test handling of empty base URL."""
        security = TatouSecurity("", self.admin_key)
        assert security.base_url == ""

    def test_none_admin_key(self):
        """Test handling of None admin key."""
        security = TatouSecurity(self.base_url, None)
        assert security.admin_key is None

    def test_very_long_url(self):
        """Test handling of very long URL."""
        long_url = "http://" + "a" * 10000 + ".com"
        security = TatouSecurity(long_url, self.admin_key)
        assert security.base_url == long_url

    @patch('security.requests.get')
    def test_network_timeout(self, mock_get):
        """Test handling of network timeout."""
        import requests
        mock_get.side_effect = requests.exceptions.Timeout()
        
        result = self.security.check_health()
        
        assert result is False
        assert self.security.metrics["failed_requests"] == 1

    @patch('security.requests.get')
    def test_connection_error(self, mock_get):
        """Test handling of connection error."""
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError()
        
        result = self.security.check_health()
        
        assert result is False
        assert self.security.metrics["failed_requests"] == 1

    def test_metrics_accumulation(self):
        """Test that metrics accumulate correctly."""
        # Generate multiple alerts
        for i in range(5):
            self.security.generate_alert(f"TEST_ALERT_{i}", f"Message {i}")
        
        assert self.security.metrics["security_alerts"] == 5

    def test_logger_initialization(self):
        """Test logger initialization and configuration."""
        security = TatouSecurity()
        assert security.logger is not None
        assert security.logger.name == "security"

    # ==================== INTEGRATION SIMULATION TESTS ====================

    @patch.object(TatouSecurity, 'check_health')
    @patch.object(TatouSecurity, 'check_security_status')
    @patch.object(TatouSecurity, 'analyze_logs')
    def test_full_monitoring_workflow(self, mock_analyze_logs, mock_check_security, mock_check_health):
        """Test complete monitoring workflow simulation."""
        # Mock health check
        mock_check_health.return_value = True
        
        # Mock security status - return the actual data structure
        mock_check_security.return_value = {
            "security_summary": {
                "suspicious_ips": ["192.168.1.1"],
                "active_login_attempts": {"192.168.1.1": 4},
                "active_request_counts": {"192.168.1.2": 2}
            }
        }
        
        # Mock log analysis
        mock_analyze_logs.return_value = {"total_security_events": 5}
        
        # Run monitoring cycle
        self.security.run_monitoring_cycle()
        
        # Verify all components were called
        mock_check_health.assert_called_once()
        mock_check_security.assert_called_once()
        mock_analyze_logs.assert_called_once()
        assert self.security.metrics["last_check"] is not None
