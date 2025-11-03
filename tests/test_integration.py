"""
Integration tests for CalmWeb.

Tests integration between components including:
- HTTP proxy functionality
- DNS resolution and blocking
- Configuration management
- System integration features
"""

import os
import sys
import socket
import threading
import time
from http.server import ThreadingHTTPServer
from unittest.mock import Mock, patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import program.calmweb as calmweb


class TestProxyIntegration:
    """Test HTTP proxy integration functionality."""

    def setup_method(self):
        """Set up test environment."""
        calmweb.block_enabled = True
        calmweb.current_resolver = None
        calmweb.proxy_server = None

    def teardown_method(self):
        """Clean up test environment."""
        if calmweb.proxy_server:
            try:
                calmweb.proxy_server.shutdown()
                calmweb.proxy_server.server_close()
            except Exception:
                pass
        calmweb.proxy_server = None

    @pytest.mark.integration
    @patch('socket.create_connection')
    def test_proxy_server_startup_and_basic_operation(self, mock_create_connection):
        """Test proxy server startup and basic operation."""
        mock_socket = Mock()
        mock_create_connection.return_value = mock_socket

        # Start proxy server
        server = calmweb.start_proxy_server("127.0.0.1", 0)  # Use port 0 for auto-assignment
        assert server is not None
        assert isinstance(server, ThreadingHTTPServer)

        # Give server time to start
        time.sleep(0.1)

        # Server should be running
        assert calmweb.proxy_server is not None
        assert calmweb.proxy_server_thread is not None

        # Cleanup
        server.shutdown()
        server.server_close()

    @pytest.mark.integration
    def test_proxy_server_error_handling(self):
        """Test proxy server error handling."""
        # Try to start server on invalid port
        with patch('calmweb.ThreadingHTTPServer', side_effect=Exception("Port in use")):
            server = calmweb.start_proxy_server("127.0.0.1", 80)
            assert server is None

    @pytest.mark.integration
    @patch('socket.create_connection')
    def test_proxy_handler_with_resolver_integration(self, mock_create_connection, mock_resolver):
        """Test proxy handler integration with BlocklistResolver."""
        mock_socket = Mock()
        mock_create_connection.return_value = mock_socket

        # Set up resolver
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = False
        mock_resolver.is_whitelisted.return_value = False
        mock_resolver.maybe_reload_background.return_value = None

        # Create handler
        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "https://example.com/test"
        handler.command = "GET"
        handler.request_version = "HTTP/1.1"
        handler.headers = {"Host": "example.com"}
        handler.connection = Mock()

        with patch('calmweb.full_duplex_relay') as mock_relay:
            calmweb.BlockProxyHandler._handle_http_method(handler)

        # Should have checked with resolver
        mock_resolver.maybe_reload_background.assert_called_once()
        mock_resolver._is_blocked.assert_called_once()

        # Should have proceeded with connection
        mock_create_connection.assert_called_once()


class TestConfigurationIntegration:
    """Test configuration management integration."""

    @pytest.mark.integration
    def test_full_configuration_lifecycle(self, temp_dir, reset_global_state):
        """Test complete configuration lifecycle."""
        config_dir = temp_dir / "calmweb_config"
        config_file = config_dir / "custom.cfg"

        # Mock paths
        with patch.object(calmweb, 'USER_CFG_DIR', str(config_dir)), \
             patch.object(calmweb, 'USER_CFG_PATH', str(config_file)):

            # 1. Ensure config exists (should create default)
            initial_blocked = {"initial-blocked.com"}
            initial_whitelist = {"initial-safe.com"}

            result_path = calmweb.ensure_custom_cfg_exists(
                None, initial_blocked, initial_whitelist
            )

            assert result_path == str(config_file)
            assert config_file.exists()

            # 2. Load configuration to globals
            blocked, whitelist = calmweb.load_custom_cfg_to_globals(str(config_file))

            assert "initial-blocked.com" in calmweb.manual_blocked_domains
            assert "initial-safe.com" in calmweb.whitelisted_domains

            # 3. Parse configuration directly
            parsed_blocked, parsed_whitelist = calmweb.parse_custom_cfg(str(config_file))

            assert "initial-blocked.com" in parsed_blocked
            assert "initial-safe.com" in parsed_whitelist

    @pytest.mark.integration
    def test_configuration_with_resolver_integration(self, temp_dir, reset_global_state):
        """Test configuration integration with BlocklistResolver."""
        # Create config file
        config_file = temp_dir / "test.cfg"
        content = """[BLOCK]
config-blocked.com
manual-malware.net

[WHITELIST]
config-safe.com
trusted.example.org

[OPTIONS]
block_ip_direct = 1
block_http_traffic = 0
block_http_other_ports = 1
"""
        config_file.write_text(content, encoding='utf-8')

        # Load config
        calmweb.load_custom_cfg_to_globals(str(config_file))

        # Create resolver
        resolver = calmweb.BlocklistResolver([])

        # Test interaction between config and resolver
        assert resolver._is_blocked("config-blocked.com") == True
        assert resolver._is_blocked("manual-malware.net") == True

        # Whitelist should override
        calmweb.whitelisted_domains.add("config-blocked.com")
        assert resolver._is_blocked("config-blocked.com") == False

        # Options should be applied
        assert calmweb.block_ip_direct == True
        assert calmweb.block_http_traffic == False
        assert calmweb.block_http_other_ports == True

    @pytest.mark.integration
    def test_configuration_reload_integration(self, temp_dir, reset_global_state, capture_logs):
        """Test configuration reload integration."""
        config_file = temp_dir / "reload_test.cfg"

        # Initial config
        initial_content = """[BLOCK]
initial-blocked.com

[WHITELIST]
initial-safe.com
"""
        config_file.write_text(initial_content, encoding='utf-8')

        # Mock paths
        with patch('calmweb.get_custom_cfg_path', return_value=str(config_file)):
            # Load initial config
            calmweb.load_custom_cfg_to_globals(str(config_file))
            assert "initial-blocked.com" in calmweb.manual_blocked_domains

            # Update config file
            updated_content = """[BLOCK]
initial-blocked.com
new-blocked.com

[WHITELIST]
initial-safe.com
new-safe.com
"""
            config_file.write_text(updated_content, encoding='utf-8')

            # Create resolver for reload test
            resolver = calmweb.BlocklistResolver([])
            calmweb.current_resolver = resolver

            # Trigger reload
            calmweb.reload_config_action()

            # Give reload threads time to complete
            time.sleep(0.2)

            # Config should be updated
            assert "new-blocked.com" in calmweb.manual_blocked_domains
            assert "new-safe.com" in calmweb.whitelisted_domains


class TestSystemIntegration:
    """Test system integration features."""

    @pytest.mark.integration
    @pytest.mark.windows
    @patch('subprocess.run')
    def test_firewall_integration(self, mock_subprocess, skip_if_not_windows):
        """Test firewall rule integration."""
        mock_subprocess.return_value.returncode = 0

        target_file = "C:\\Program Files\\CalmWeb\\calmweb.exe"
        calmweb.add_firewall_rule(target_file)

        # Should have called netsh
        mock_subprocess.assert_called_once()
        args = mock_subprocess.call_args[0][0]
        assert "netsh" in args[0]
        assert "advfirewall" in args
        assert target_file in args

    @pytest.mark.integration
    @pytest.mark.windows
    @patch('subprocess.run')
    @patch('winreg.OpenKey')
    @patch('winreg.SetValueEx')
    @patch('winreg.CloseKey')
    def test_system_proxy_integration(self, mock_close, mock_set, mock_open, mock_subprocess, mock_win32_modules):
        """Test system proxy configuration integration."""
        mock_subprocess.return_value.returncode = 0
        mock_key = Mock()
        mock_open.return_value = mock_key

        # Enable proxy
        calmweb.set_system_proxy(enable=True, host="127.0.0.1", port=8080)

        # Should have called netsh and registry functions
        assert mock_subprocess.called
        mock_open.assert_called()
        mock_set.assert_called()

        # Disable proxy
        mock_subprocess.reset_mock()
        mock_open.reset_mock()
        mock_set.reset_mock()

        calmweb.set_system_proxy(enable=False)

        # Should have called reset commands
        assert mock_subprocess.called

    @pytest.mark.integration
    @patch('os.makedirs')
    @patch('shutil.copy')
    @patch('subprocess.run')
    @patch('tempfile.NamedTemporaryFile')
    @patch('os.startfile')
    def test_installation_integration(self, mock_startfile, mock_tempfile, mock_subprocess,
                                     mock_copy, mock_makedirs, temp_dir, capture_logs):
        """Test installation process integration."""
        # Mock file operations
        mock_temp_file = Mock()
        mock_temp_file.name = str(temp_dir / "temp.xml")
        mock_tempfile.return_value.__enter__.return_value = mock_temp_file

        mock_subprocess.return_value.returncode = 0

        # Mock sys.argv and installation directory
        with patch('sys.argv', ['calmweb.py']), \
             patch.object(calmweb, 'INSTALL_DIR', str(temp_dir / "install")), \
             patch('os.path.exists', return_value=False):

            # Should not crash during installation
            try:
                # Don't actually call install() as it calls sys.exit()
                # Instead test individual components

                # Test config creation
                config_path = calmweb.ensure_custom_cfg_exists(
                    str(temp_dir / "install"),
                    {"test.com"},
                    {"safe.com"}
                )
                assert config_path is not None

                # Test firewall rule addition
                calmweb.add_firewall_rule("test.exe")
                assert mock_subprocess.called

            except SystemExit:
                # Expected from install() function
                pass


class TestNetworkIntegration:
    """Test network and DNS integration."""

    @pytest.mark.integration
    @pytest.mark.network
    @patch('urllib3.PoolManager')
    def test_blocklist_download_integration(self, mock_pool_manager):
        """Test blocklist download integration."""
        # Mock successful HTTP response
        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = b"""# Test blocklist
0.0.0.0 malware.example.com
127.0.0.1 phishing.test
ads.badsite.net
tracking.evil.com
"""
        mock_pool_manager.return_value.request.return_value = mock_response

        # Create resolver with test URL
        test_urls = ["http://example.com/blocklist.txt"]
        resolver = calmweb.BlocklistResolver(test_urls)

        # Load blocklist
        resolver._load_blocklist()

        # Should have downloaded and parsed domains
        assert "malware.example.com" in resolver.blocked_domains
        assert "phishing.test" in resolver.blocked_domains
        assert "ads.badsite.net" in resolver.blocked_domains

    @pytest.mark.integration
    @pytest.mark.network
    @patch('urllib3.PoolManager')
    def test_whitelist_download_integration(self, mock_pool_manager):
        """Test whitelist download integration."""
        # Mock successful HTTP response
        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = b"""# Test whitelist
google.com
*.microsoft.com
github.com
192.168.1.0/24
10.0.0.1
"""
        mock_pool_manager.return_value.request.return_value = mock_response

        with patch.object(calmweb, 'WHITELIST_URLS', ["http://example.com/whitelist.txt"]):
            resolver = calmweb.BlocklistResolver([])
            resolver._load_whitelist()

        # Should have downloaded and parsed domains
        assert "google.com" in resolver.whitelisted_domains_local
        assert "microsoft.com" in resolver.whitelisted_domains_local
        assert "github.com" in resolver.whitelisted_domains_local

    @pytest.mark.integration
    def test_ip_address_detection_integration(self):
        """Test IP address detection integration."""
        resolver = calmweb.BlocklistResolver([])

        # IPv4 addresses
        assert resolver._looks_like_ip("192.168.1.1") == True
        assert resolver._looks_like_ip("10.0.0.1") == True
        assert resolver._looks_like_ip("127.0.0.1") == True

        # IPv6 addresses
        assert resolver._looks_like_ip("::1") == True
        assert resolver._looks_like_ip("2001:db8::1") == True

        # Not IP addresses
        assert resolver._looks_like_ip("example.com") == False
        assert resolver._looks_like_ip("not-an-ip") == False

    @pytest.mark.integration
    def test_domain_blocking_integration(self, reset_global_state):
        """Test complete domain blocking integration."""
        # Set up global domains
        calmweb.manual_blocked_domains.clear()
        calmweb.manual_blocked_domains.update({
            "manual-blocked.com",
            "scam.evil.org"
        })

        calmweb.whitelisted_domains.clear()
        calmweb.whitelisted_domains.update({
            "trusted.example.com",
            "safe.site.org"
        })

        # Create resolver with additional blocked domains
        resolver = calmweb.BlocklistResolver([])
        resolver.blocked_domains = {
            "resolver-blocked.com",
            "malware.net"
        }

        # Test blocking logic
        assert resolver._is_blocked("manual-blocked.com") == True
        assert resolver._is_blocked("resolver-blocked.com") == True
        assert resolver._is_blocked("scam.evil.org") == True

        # Test subdomain blocking
        assert resolver._is_blocked("sub.manual-blocked.com") == True
        assert resolver._is_blocked("deep.sub.resolver-blocked.com") == True

        # Test whitelist priority
        assert resolver._is_blocked("trusted.example.com") == False
        assert resolver._is_blocked("sub.trusted.example.com") == False

        # Test clean domains
        assert resolver._is_blocked("clean.example.com") == False


class TestErrorHandlingIntegration:
    """Test error handling integration across components."""

    @pytest.mark.integration
    @patch('urllib3.PoolManager')
    def test_resolver_network_error_integration(self, mock_pool_manager, capture_logs):
        """Test resolver handles network errors gracefully."""
        # Mock network failures to avoid actual network calls
        mock_pool_manager.return_value.request.side_effect = Exception("Network error")

        # Use invalid URLs that would cause network errors
        invalid_urls = [
            "http://nonexistent.invalid.domain.test/blocklist.txt",
            "https://invalid-protocol://malformed-url",
            "not-a-url-at-all"
        ]

        resolver = calmweb.BlocklistResolver(invalid_urls)

        # Should handle errors gracefully
        try:
            resolver._load_blocklist()
            # Should not crash
        except Exception:
            pytest.fail("Resolver should handle network errors gracefully")

    @pytest.mark.integration
    def test_proxy_handler_error_integration(self, mock_resolver, capture_logs):
        """Test proxy handler error integration."""
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = False
        mock_resolver.is_whitelisted.return_value = False

        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "https://example.com/test"
        handler.command = "GET"
        handler.request_version = "HTTP/1.1"
        handler.headers = {"Host": "example.com"}
        handler.connection = Mock()
        handler.send_error = Mock()

        # Simulate connection failure
        with patch('socket.create_connection', side_effect=Exception("Network error")):
            calmweb.BlockProxyHandler._handle_http_method(handler)

        # Should handle error gracefully
        handler.send_error.assert_called_with(502, "Bad Gateway")

    @pytest.mark.integration
    def test_configuration_error_integration(self, temp_dir, reset_global_state, capture_logs):
        """Test configuration error handling integration."""
        # Create corrupted config file
        corrupted_config = temp_dir / "corrupted.cfg"

        # Write binary data that will cause encoding errors
        with open(corrupted_config, 'wb') as f:
            f.write(b'\xff\xfe\x00\x01[BLOCK]\n\xff\xfemalicious.com\n')

        # Should handle corrupted config gracefully
        try:
            blocked, whitelist = calmweb.parse_custom_cfg(str(corrupted_config))
            assert isinstance(blocked, set)
            assert isinstance(whitelist, set)
        except Exception:
            pytest.fail("Should handle corrupted config files gracefully")


class TestPerformanceIntegration:
    """Test performance aspects of integration."""

    @pytest.mark.integration
    @pytest.mark.slow
    def test_large_blocklist_performance(self):
        """Test performance with large blocklists."""
        # Create resolver with large domain set
        resolver = calmweb.BlocklistResolver([])

        # Add many domains
        large_blocklist = set()
        for i in range(50000):
            large_blocklist.add(f"domain{i}.com")

        resolver.blocked_domains = large_blocklist

        # Test lookup performance
        start_time = time.time()

        # Perform many lookups
        for i in range(1000):
            resolver._is_blocked(f"domain{i * 50}.com")
            resolver._is_blocked(f"notfound{i}.com")

        end_time = time.time()

        # Should complete within reasonable time (less than 1 second)
        assert (end_time - start_time) < 1.0

    @pytest.mark.integration
    @pytest.mark.slow
    def test_concurrent_operations_performance(self, mock_resolver):
        """Test performance under concurrent operations."""
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = False
        mock_resolver.is_whitelisted.return_value = False

        def simulate_requests():
            for i in range(100):
                handler = Mock(spec=calmweb.BlockProxyHandler)
                handler.path = f"https://example{i}.com/test"
                handler.command = "GET"
                handler.request_version = "HTTP/1.1"
                handler.headers = {"Host": f"example{i}.com"}
                handler.connection = Mock()

                with patch('socket.create_connection'):
                    with patch('calmweb.full_duplex_relay'):
                        try:
                            calmweb.BlockProxyHandler._handle_http_method(handler)
                        except Exception:
                            pass  # Ignore errors for performance test

        # Run concurrent simulations
        start_time = time.time()

        threads = []
        for _ in range(10):
            thread = threading.Thread(target=simulate_requests)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        end_time = time.time()

        # Should handle concurrent operations efficiently
        total_requests = 10 * 100
        time_per_request = (end_time - start_time) / total_requests

        # Should process requests quickly (less than 10ms per request average)
        assert time_per_request < 0.01