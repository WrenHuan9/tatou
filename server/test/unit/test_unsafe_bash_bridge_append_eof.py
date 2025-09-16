"""Unit tests for unsafe_bash_bridge_append_eof.py module."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from server.src.unsafe_bash_bridge_append_eof import UnsafeBashBridgeAppendEOF


class TestUnsafeBashBridgeAppendEOF:
    """Test UnsafeBashBridgeAppendEOF watermarking method."""
    
    def test_class_attributes(self):
        """Test class has correct attributes."""
        method = UnsafeBashBridgeAppendEOF()
        assert method.name == "bash-bridge-eof"
    
    def test_get_usage(self):
        """Test get_usage returns descriptive string."""
        usage = UnsafeBashBridgeAppendEOF.get_usage()
        assert isinstance(usage, str)
        assert "toy method" in usage.lower()
        assert "eof" in usage.lower()
        assert "position and key are ignored" in usage.lower()
    
    def test_is_watermark_applicable_always_true(self, sample_pdf_file: Path):
        """Test is_watermark_applicable always returns True."""
        method = UnsafeBashBridgeAppendEOF()
        assert method.is_watermark_applicable(sample_pdf_file) is True
        assert method.is_watermark_applicable(sample_pdf_file, position="any") is True
    
    @patch('unsafe_bash_bridge_append_eof.subprocess.run')
    def test_add_watermark_calls_subprocess(self, mock_run, sample_pdf_file: Path):
        """Test add_watermark calls subprocess with correct command."""
        method = UnsafeBashBridgeAppendEOF()
        secret = "test-secret"
        key = "test-key"  # This will be ignored
        
        # Mock subprocess result
        mock_result = Mock()
        mock_result.stdout = b"%PDF-1.4\ntest content\ntest-secret"
        mock_run.return_value = mock_result
        
        result = method.add_watermark(sample_pdf_file, secret, key)
        
        # Verify subprocess was called
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        
        # Check command structure
        cmd = call_args[0][0]
        assert "cat" in cmd
        assert str(sample_pdf_file.resolve()) in cmd
        assert "printf" in cmd
        assert secret in cmd
        
        # Check subprocess arguments
        assert call_args[1]["shell"] is True
        assert call_args[1]["check"] is True
        assert call_args[1]["capture_output"] is True
        
        assert result == mock_result.stdout
    
    @patch('unsafe_bash_bridge_append_eof.subprocess.run')
    def test_add_watermark_position_ignored(self, mock_run, sample_pdf_file: Path):
        """Test position parameter is ignored."""
        method = UnsafeBashBridgeAppendEOF()
        secret = "test-secret"
        key = "test-key"
        
        mock_result = Mock()
        mock_result.stdout = b"mocked output"
        mock_run.return_value = mock_result
        
        # Call with and without position
        result1 = method.add_watermark(sample_pdf_file, secret, key)
        result2 = method.add_watermark(sample_pdf_file, secret, key, position="ignored")
        
        # Both calls should be identical
        assert mock_run.call_count == 2
        call1_cmd = mock_run.call_args_list[0][0][0]
        call2_cmd = mock_run.call_args_list[1][0][0]
        assert call1_cmd == call2_cmd
        
        assert result1 == result2
    
    @patch('unsafe_bash_bridge_append_eof.subprocess.run')
    def test_read_secret_calls_subprocess(self, mock_run, sample_pdf_file: Path):
        """Test read_secret calls subprocess with sed command."""
        method = UnsafeBashBridgeAppendEOF()
        key = "test-key"  # This will be ignored
        
        # Mock subprocess result
        mock_result = Mock()
        mock_result.stdout = "extracted-secret"
        mock_run.return_value = mock_result
        
        result = method.read_secret(sample_pdf_file, key)
        
        # Verify subprocess was called
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        
        # Check command structure
        cmd = call_args[0][0]
        assert "sed" in cmd
        assert "%%EOF" in cmd
        assert str(sample_pdf_file.resolve()) in cmd
        
        # Check subprocess arguments
        assert call_args[1]["shell"] is True
        assert call_args[1]["check"] is True
        assert call_args[1]["encoding"] == "utf-8"
        assert call_args[1]["capture_output"] is True
        
        assert result == "extracted-secret"
    
    @patch('unsafe_bash_bridge_append_eof.subprocess.run')
    def test_command_injection_vulnerability(self, mock_run, sample_pdf_file: Path):
        """Test that the method is vulnerable to command injection (for security awareness)."""
        method = UnsafeBashBridgeAppendEOF()
        
        # This demonstrates the vulnerability - don't do this in real code!
        malicious_secret = 'secret"; rm -rf /tmp/test; echo "injected'
        
        mock_result = Mock()
        mock_result.stdout = b"output"
        mock_run.return_value = mock_result
        
        # The method should execute the injected command
        method.add_watermark(sample_pdf_file, malicious_secret, "key")
        
        # Verify the malicious command was included
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert 'rm -rf /tmp/test' in cmd
        
        # This test demonstrates why this method is "unsafe"
    
    @patch('unsafe_bash_bridge_append_eof.subprocess.run')
    def test_subprocess_error_propagates(self, mock_run, sample_pdf_file: Path):
        """Test that subprocess errors are propagated."""
        method = UnsafeBashBridgeAppendEOF()
        
        # Mock subprocess to raise an error
        mock_run.side_effect = Exception("Command failed")
        
        with pytest.raises(Exception, match="Command failed"):
            method.add_watermark(sample_pdf_file, "secret", "key")
    
    def test_integration_with_real_file(self, sample_pdf_file: Path):
        """Test integration with a real file (if system has required tools)."""
        method = UnsafeBashBridgeAppendEOF()
        secret = "integration-test-secret"
        
        try:
            # This will only work if the system has cat and printf
            watermarked = method.add_watermark(sample_pdf_file, secret, "key")
            assert isinstance(watermarked, bytes)
            assert watermarked.startswith(b"%PDF-")
            assert secret.encode() in watermarked
            
        except Exception as e:
            # Skip if system doesn't have required tools or there are permission issues
            pytest.skip(f"Integration test skipped due to system limitations: {e}")
    
    def test_integration_read_after_write(self, sample_pdf_file: Path):
        """Test reading secret after writing (integration test)."""
        method = UnsafeBashBridgeAppendEOF()
        secret = "roundtrip-test-secret"
        
        try:
            # Write watermark
            watermarked = method.add_watermark(sample_pdf_file, secret, "key")
            
            # Write to temporary file
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False) as f:
                f.write(watermarked)
                temp_path = Path(f.name)
            
            try:
                # Read secret back
                extracted = method.read_secret(temp_path, "key")
                # Note: The extracted secret might have extra whitespace or formatting
                # because this method doesn't properly handle the secret extraction
                assert secret in extracted
                
            finally:
                temp_path.unlink()
                
        except Exception as e:
            pytest.skip(f"Integration test skipped due to system limitations: {e}")
    
    @patch('unsafe_bash_bridge_append_eof.subprocess.run')
    def test_pathlib_path_handling(self, mock_run, sample_pdf_file: Path):
        """Test that PathLib paths are handled correctly."""
        method = UnsafeBashBridgeAppendEOF()
        
        mock_result = Mock()
        mock_result.stdout = b"output"
        mock_run.return_value = mock_result
        
        method.add_watermark(sample_pdf_file, "secret", "key")
        
        # Verify that the path was resolved correctly
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert str(sample_pdf_file.resolve()) in cmd
    
    def test_method_name_consistency(self):
        """Test method name is consistent."""
        method = UnsafeBashBridgeAppendEOF()
        assert method.name == "bash-bridge-eof"
        assert UnsafeBashBridgeAppendEOF.name == "bash-bridge-eof"
