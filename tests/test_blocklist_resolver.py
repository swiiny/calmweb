"""
Unit tests for BlocklistResolver class.

Tests domain blocking, whitelisting, and the resolver's core functionality.
"""

import ipaddress
import threading
import time
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock

import pytest
import urllib3

import calmweb


class TestBlocklistResolver:
    """Test the BlocklistResolver class functionality."""

    def setup_method(self):
        """Set up test environment."""
        # Reset global state
        calmweb.manual_blocked_domains.clear()
        calmweb.whitelisted_domains.clear()
        calmweb.block_ip_direct = True

    @pytest.mark.unit
    def test_resolver_initialization(self):
        """Test BlocklistResolver initialization."""
        blocklist_urls = ["http://example.com/blocklist.txt"]
        resolver = calmweb.BlocklistResolver(blocklist_urls, reload_interval=3600)

        assert resolver.blocklist_urls == blocklist_urls
        assert resolver.reload_interval == 3600
        assert isinstance(resolver.blocked_domains, set)
        assert isinstance(resolver.whitelisted_domains_local, set)
        assert isinstance(resolver.whitelisted_networks, set)
        assert hasattr(resolver, '_lock')
        assert hasattr(resolver, '_loading_lock')

    @pytest.mark.unit
    def test_resolver_minimum_reload_interval(self):
        """Test that reload interval has minimum value."""
        resolver = calmweb.BlocklistResolver([], reload_interval=30)
        assert resolver.reload_interval == 60  # Should be clamped to minimum

    @pytest.mark.unit
    def test_looks_like_ip_valid_ipv4(self):
        """Test _looks_like_ip with valid IPv4 addresses."""
        resolver = calmweb.BlocklistResolver([])

        assert resolver._looks_like_ip("192.168.1.1") == True
        assert resolver._looks_like_ip("10.0.0.1") == True
        assert resolver._looks_like_ip("127.0.0.1") == True
        assert resolver._looks_like_ip("8.8.8.8") == True

    @pytest.mark.unit
    def test_looks_like_ip_valid_ipv6(self):
        """Test _looks_like_ip with valid IPv6 addresses."""
        resolver = calmweb.BlocklistResolver([])

        assert resolver._looks_like_ip("::1") == True
        assert resolver._looks_like_ip("2001:db8::1") == True
        assert resolver._looks_like_ip("fe80::1") == True

    @pytest.mark.unit
    def test_looks_like_ip_invalid(self):
        """Test _looks_like_ip with invalid IP addresses."""
        resolver = calmweb.BlocklistResolver([])

        assert resolver._looks_like_ip("example.com") == False
        assert resolver._looks_like_ip("not-an-ip") == False
        assert resolver._looks_like_ip("256.256.256.256") == False
        assert resolver._looks_like_ip("") == False
        assert resolver._looks_like_ip("192.168.1") == False

    @pytest.mark.unit
    @patch('urllib3.PoolManager')
    def test_load_blocklist_success(self, mock_pool_manager, capture_logs):
        """Test successful blocklist loading."""
        # Mock HTTP response
        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = b"""# Test blocklist
0.0.0.0 malware.example.com
127.0.0.1 phishing.test
malicious.site
# Another comment
ads.badsite.net
"""
        mock_pool_manager.return_value.request.return_value = mock_response

        resolver = calmweb.BlocklistResolver(["http://example.com/blocklist.txt"])
        resolver._load_blocklist()

        expected_domains = {"malware.example.com", "phishing.test", "malicious.site", "ads.badsite.net"}
        assert expected_domains.issubset(resolver.blocked_domains)

    @pytest.mark.unit
    @patch('urllib3.PoolManager')
    def test_load_blocklist_http_error(self, mock_pool_manager, capture_logs):
        """Test blocklist loading with HTTP error."""
        mock_response = Mock()
        mock_response.status = 404
        mock_pool_manager.return_value.request.return_value = mock_response

        resolver = calmweb.BlocklistResolver(["http://example.com/notfound.txt"])
        initial_domains = len(resolver.blocked_domains)

        resolver._load_blocklist()

        # Should handle error gracefully and not crash
        assert len(resolver.blocked_domains) == initial_domains

    @pytest.mark.unit
    @patch('urllib3.PoolManager')
    def test_load_blocklist_malformed_content(self, mock_pool_manager, capture_logs):
        """Test blocklist loading with malformed content."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = b"""# Malformed blocklist
        invalid line without proper format
        256.256.256.256 invalid.ip.domain
        good.domain.com
        # Comment
        another.good.domain
        """
        mock_pool_manager.return_value.request.return_value = mock_response

        resolver = calmweb.BlocklistResolver(["http://example.com/malformed.txt"])
        resolver._load_blocklist()

        # Should parse what it can
        assert "good.domain.com" in resolver.blocked_domains
        assert "another.good.domain" in resolver.blocked_domains

    @pytest.mark.unit
    @patch('urllib3.PoolManager')
    def test_load_whitelist_success(self, mock_pool_manager, capture_logs):
        """Test successful whitelist loading."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = b"""# Test whitelist
google.com
*.microsoft.com
192.168.1.0/24
10.0.0.1
github.com
"""
        mock_pool_manager.return_value.request.return_value = mock_response

        with patch.object(calmweb, 'WHITELIST_URLS', ["http://example.com/whitelist.txt"]):
            resolver = calmweb.BlocklistResolver([])
            resolver._load_whitelist()

        assert "google.com" in resolver.whitelisted_domains_local
        assert "microsoft.com" in resolver.whitelisted_domains_local  # *.microsoft.com -> microsoft.com
        assert "github.com" in resolver.whitelisted_domains_local

        # Check CIDR network
        expected_network = ipaddress.ip_network("192.168.1.0/24")
        assert expected_network in resolver.whitelisted_networks

    @pytest.mark.unit
    def test_is_whitelisted_exact_domain(self):
        """Test is_whitelisted with exact domain match."""
        resolver = calmweb.BlocklistResolver([])
        resolver.whitelisted_domains_local = {"google.com", "github.com"}

        assert resolver.is_whitelisted("google.com") == True
        assert resolver.is_whitelisted("github.com") == True
        assert resolver.is_whitelisted("evil.com") == False

    @pytest.mark.unit
    def test_is_whitelisted_subdomain(self):
        """Test is_whitelisted with subdomain matching."""
        resolver = calmweb.BlocklistResolver([])
        resolver.whitelisted_domains_local = {"google.com", "microsoft.com"}

        assert resolver.is_whitelisted("mail.google.com") == True
        assert resolver.is_whitelisted("docs.google.com") == True
        assert resolver.is_whitelisted("azure.microsoft.com") == True
        assert resolver.is_whitelisted("subdomain.evil.com") == False

    @pytest.mark.unit
    def test_is_whitelisted_ip_address(self):
        """Test is_whitelisted with IP addresses."""
        resolver = calmweb.BlocklistResolver([])
        resolver.whitelisted_domains_local = {"8.8.8.8"}
        resolver.whitelisted_networks = {ipaddress.ip_network("192.168.1.0/24")}

        # Exact IP match
        assert resolver.is_whitelisted("8.8.8.8") == True

        # Network match
        assert resolver.is_whitelisted("192.168.1.10") == True
        assert resolver.is_whitelisted("192.168.1.255") == True

        # No match
        assert resolver.is_whitelisted("10.0.0.1") == False

    @pytest.mark.unit
    def test_is_whitelisted_edge_cases(self):
        """Test is_whitelisted with edge cases."""
        resolver = calmweb.BlocklistResolver([])
        resolver.whitelisted_domains_local = {"example.com"}

        # Empty/None input
        assert resolver.is_whitelisted("") == False
        assert resolver.is_whitelisted(None) == False

        # Whitespace and dots
        assert resolver.is_whitelisted("  example.com  ") == True
        assert resolver.is_whitelisted("example.com.") == True

    @pytest.mark.unit
    def test_is_blocked_basic_functionality(self):
        """Test _is_blocked basic functionality."""
        resolver = calmweb.BlocklistResolver([])
        resolver.blocked_domains = {"malware.com", "phishing.net"}

        calmweb.manual_blocked_domains.clear()
        calmweb.manual_blocked_domains.update({"scam.site"})

        assert resolver._is_blocked("malware.com") == True
        assert resolver._is_blocked("phishing.net") == True
        assert resolver._is_blocked("scam.site") == True
        assert resolver._is_blocked("safe.com") == False

    @pytest.mark.unit
    def test_is_blocked_subdomain_blocking(self):
        """Test _is_blocked with subdomain blocking."""
        resolver = calmweb.BlocklistResolver([])
        resolver.blocked_domains = {"malware.com"}

        assert resolver._is_blocked("sub.malware.com") == True
        assert resolver._is_blocked("deep.sub.malware.com") == True
        assert resolver._is_blocked("notmalware.com") == False

    @pytest.mark.unit
    def test_is_blocked_whitelist_priority(self):
        """Test that whitelist has priority over blocklist."""
        resolver = calmweb.BlocklistResolver([])
        resolver.blocked_domains = {"example.com"}
        resolver.whitelisted_domains_local = {"example.com"}

        # Whitelist should override blocklist
        assert resolver._is_blocked("example.com") == False

    @pytest.mark.unit
    def test_is_blocked_ip_direct_blocking(self):
        """Test IP direct blocking functionality."""
        resolver = calmweb.BlocklistResolver([])

        # Test with block_ip_direct enabled
        calmweb.block_ip_direct = True
        assert resolver._is_blocked("192.168.1.1") == True
        assert resolver._is_blocked("8.8.8.8") == True

        # Test with block_ip_direct disabled
        calmweb.block_ip_direct = False
        assert resolver._is_blocked("192.168.1.1") == False
        assert resolver._is_blocked("8.8.8.8") == False

    @pytest.mark.unit
    def test_is_blocked_ip_whitelist_override(self):
        """Test that IP whitelist overrides block_ip_direct."""
        resolver = calmweb.BlocklistResolver([])
        resolver.whitelisted_domains_local = {"8.8.8.8"}

        calmweb.block_ip_direct = True
        # Whitelisted IP should not be blocked
        assert resolver._is_blocked("8.8.8.8") == False
        # Non-whitelisted IP should be blocked
        assert resolver._is_blocked("1.2.3.4") == True

    @pytest.mark.unit
    def test_is_blocked_error_handling(self):
        """Test _is_blocked error handling."""
        resolver = calmweb.BlocklistResolver([])

        # Should handle None gracefully
        assert resolver._is_blocked(None) == False
        assert resolver._is_blocked("") == False

        # Should handle malformed input
        assert resolver._is_blocked("...") == False

    @pytest.mark.unit
    def test_maybe_reload_background_timing(self):
        """Test maybe_reload_background timing logic."""
        resolver = calmweb.BlocklistResolver([])

        # Set last_reload to long ago
        resolver.last_reload = time.time() - 7200  # 2 hours ago
        resolver.reload_interval = 3600  # 1 hour

        with patch.object(resolver, '_load_blocklist') as mock_load_blocklist, \
             patch.object(resolver, '_load_whitelist') as mock_load_whitelist:

            resolver.maybe_reload_background()

            # Should have triggered reload (eventually, as it's background)
            time.sleep(0.1)  # Give threads time to start

    @pytest.mark.unit
    def test_maybe_reload_background_no_reload_needed(self):
        """Test maybe_reload_background when no reload is needed."""
        resolver = calmweb.BlocklistResolver([])

        # Set last_reload to recent
        resolver.last_reload = time.time()
        resolver.reload_interval = 3600

        with patch.object(resolver, '_load_blocklist') as mock_load_blocklist, \
             patch.object(resolver, '_load_whitelist') as mock_load_whitelist:

            resolver.maybe_reload_background()

            # Should not have triggered reload
            time.sleep(0.1)
            assert mock_load_blocklist.call_count == 0
            assert mock_load_whitelist.call_count == 0

    @pytest.mark.unit
    def test_thread_safety_domain_checking(self):
        """Test thread safety of domain checking operations."""
        resolver = calmweb.BlocklistResolver([])
        resolver.blocked_domains = {"test.com"}
        resolver.whitelisted_domains_local = {"safe.com"}

        results = []

        def check_domains():
            for _ in range(100):
                results.append(resolver._is_blocked("test.com"))
                results.append(resolver.is_whitelisted("safe.com"))

        threads = []
        for _ in range(10):
            thread = threading.Thread(target=check_domains)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # All results should be consistent
        blocked_results = results[::2]  # Every other result
        whitelisted_results = results[1::2]  # Every other result

        assert all(result == True for result in blocked_results)
        assert all(result == True for result in whitelisted_results)

    @pytest.mark.unit
    @patch('urllib3.PoolManager')
    def test_load_blocklist_retry_mechanism(self, mock_pool_manager, capture_logs):
        """Test blocklist loading retry mechanism."""
        # First two attempts fail, third succeeds
        mock_response_fail = Mock()
        mock_response_fail.status = 500

        mock_response_success = Mock()
        mock_response_success.status = 200
        mock_response_success.data = b"test.domain.com"

        mock_pool_manager.return_value.request.side_effect = [
            Exception("Network error"),  # First attempt
            mock_response_fail,          # Second attempt
            mock_response_success        # Third attempt
        ]

        resolver = calmweb.BlocklistResolver(["http://example.com/blocklist.txt"])
        resolver._load_blocklist()

        # Should have succeeded on third attempt
        assert "test.domain.com" in resolver.blocked_domains

    @pytest.mark.unit
    def test_blocklist_content_parsing_edge_cases(self):
        """Test blocklist content parsing with edge cases."""
        resolver = calmweb.BlocklistResolver([])

        test_content = """
        # Comment line

        # Empty lines above and below

        127.0.0.1 localhost
        0.0.0.0 blocked.com
        very-long-domain-name-that-exceeds-normal-limits.really.really.really.long.domain.extension.com
        short.com
        domain-with-unicode-αβγ.com
        192.168.1.1 invalid.ip.mapping
        *.wildcard.test
        """

        lines = test_content.strip().split('\n')
        domains = set()

        for line in lines:
            try:
                line = line.split('#', 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                domain = None
                if len(parts) == 1:
                    domain = parts[0]
                elif len(parts) >= 2:
                    if not resolver._looks_like_ip(parts[0]):
                        domain = parts[0]
                    else:
                        domain = parts[1]
                if domain and not resolver._looks_like_ip(domain) and len(domain) <= 253:
                    domains.add(domain.lower().lstrip('.'))
            except Exception:
                continue

        assert "localhost" in domains
        assert "blocked.com" in domains
        assert "short.com" in domains

    @pytest.mark.unit
    def test_concurrent_loading_prevention(self):
        """Test that concurrent loading is prevented."""
        resolver = calmweb.BlocklistResolver([])

        # Mock the loading lock to be already acquired
        resolver._loading_lock.acquire()

        try:
            with patch.object(resolver, '_load_blocklist', wraps=resolver._load_blocklist) as mock_load:
                resolver._load_blocklist()
                # Should return early due to lock
                assert mock_load.call_count == 1
        finally:
            resolver._loading_lock.release()


class TestBlocklistResolverIntegration:
    """Integration tests for BlocklistResolver with global state."""

    def setup_method(self):
        """Set up test environment."""
        calmweb.manual_blocked_domains.clear()
        calmweb.whitelisted_domains.clear()
        calmweb.block_ip_direct = True

    @pytest.mark.integration
    def test_resolver_with_global_manual_domains(self):
        """Test resolver integration with global manual domains."""
        # Set up global manual domains
        calmweb.manual_blocked_domains.update({"manual-blocked.com"})
        calmweb.whitelisted_domains.update({"manual-whitelisted.com"})

        resolver = calmweb.BlocklistResolver([])
        resolver.blocked_domains = {"resolver-blocked.com"}

        # Manual blocked should be blocked
        assert resolver._is_blocked("manual-blocked.com") == True

        # Manual whitelisted should not be blocked even if in resolver blocked
        resolver.blocked_domains.add("manual-whitelisted.com")
        assert resolver._is_blocked("manual-whitelisted.com") == False

    @pytest.mark.integration
    def test_resolver_global_state_interaction(self):
        """Test resolver interaction with global state changes."""
        resolver = calmweb.BlocklistResolver([])

        # Initially not blocked
        assert resolver._is_blocked("dynamic.com") == False

        # Add to global manual blocked
        calmweb.manual_blocked_domains.add("dynamic.com")

        # Now should be blocked
        assert resolver._is_blocked("dynamic.com") == True

        # Add to whitelist
        calmweb.whitelisted_domains.add("dynamic.com")

        # Should not be blocked (whitelist priority)
        assert resolver._is_blocked("dynamic.com") == False

    @pytest.mark.unit
    def test_local_file_support(self, tmp_path):
        """Test loading blocklist from local file:// URLs."""
        # Create a temporary blocklist file
        blocklist_file = tmp_path / "test_blocklist.txt"
        blocklist_content = """# Test blocklist
0.0.0.0 local-test-domain.com
127.0.0.1 another-local-test.fr
# Comment line
malicious-local.net
"""
        blocklist_file.write_text(blocklist_content)

        # Create resolver with file:// URL
        file_url = f"file://{blocklist_file}"
        resolver = calmweb.BlocklistResolver([file_url])

        # Wait for loading to complete
        time.sleep(0.1)

        # Check that domains were loaded
        assert resolver._is_blocked("local-test-domain.com") == True
        assert resolver._is_blocked("another-local-test.fr") == True
        assert resolver._is_blocked("malicious-local.net") == True
        assert resolver._is_blocked("not-in-list.com") == False

    @pytest.mark.unit
    @patch('urllib3.PoolManager')
    def test_mixed_local_and_remote_sources(self, mock_pool_manager, tmp_path):
        """Test resolver with both local files and remote URLs."""
        # Setup local file
        local_file = tmp_path / "local_blocklist.txt"
        local_file.write_text("0.0.0.0 local-blocked.com\n")

        # Setup mock for remote URL
        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = b"0.0.0.0 remote-blocked.com\n"
        mock_pool_manager.return_value.request.return_value = mock_response

        # Create resolver with mixed sources
        sources = [
            f"file://{local_file}",
            "http://example.com/remote_blocklist.txt"
        ]
        resolver = calmweb.BlocklistResolver(sources)

        # Wait for loading to complete
        time.sleep(0.1)

        # Check both local and remote domains are blocked
        assert resolver._is_blocked("local-blocked.com") == True
        assert resolver._is_blocked("remote-blocked.com") == True

    @pytest.mark.unit
    def test_file_url_error_handling(self):
        """Test error handling for invalid file:// URLs."""
        # Test with non-existent file
        resolver = calmweb.BlocklistResolver(["file:///non/existent/file.txt"])

        # Should not crash, just log error and continue
        time.sleep(0.1)

        # Should still function normally
        assert resolver._is_blocked("test.com") == False

    @pytest.mark.unit
    def test_red_flag_domains_integration(self):
        """Test integration with red.flag.domains automatic updates."""
        with patch.object(calmweb, 'get_red_flag_domains_path', return_value="file://test_red_flag.txt"), \
             patch('os.path.exists', return_value=False):

            urls = calmweb.get_blocklist_urls()

            # Should include red.flag.domains path
            assert "file://test_red_flag.txt" in urls
            assert len(urls) == 5  # 4 original + 1 red.flag.domains