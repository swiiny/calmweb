"""
Unit tests for core CalmWeb functions.

Tests the fundamental utility functions including:
- _safe_str() function
- log() function with deque optimization
- Configuration parsing functions
- Thread safety mechanisms
"""

import threading
import time
import tempfile
import os
from collections import deque
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, mock_open

import pytest

import calmweb


class TestSafeStr:
    """Test the _safe_str() function for safe string conversion."""

    @pytest.mark.unit
    def test_safe_str_normal_string(self):
        """Test _safe_str with normal string input."""
        result = calmweb._safe_str("normal string")
        assert result == "normal string"

    @pytest.mark.unit
    def test_safe_str_integer(self):
        """Test _safe_str with integer input."""
        result = calmweb._safe_str(42)
        assert result == "42"

    @pytest.mark.unit
    def test_safe_str_float(self):
        """Test _safe_str with float input."""
        result = calmweb._safe_str(3.14)
        assert result == "3.14"

    @pytest.mark.unit
    def test_safe_str_none(self):
        """Test _safe_str with None input."""
        result = calmweb._safe_str(None)
        assert result == "None"

    @pytest.mark.unit
    def test_safe_str_list(self):
        """Test _safe_str with list input."""
        test_list = [1, 2, 3]
        result = calmweb._safe_str(test_list)
        assert result == "[1, 2, 3]"

    @pytest.mark.unit
    def test_safe_str_dict(self):
        """Test _safe_str with dict input."""
        test_dict = {"key": "value"}
        result = calmweb._safe_str(test_dict)
        assert "key" in result and "value" in result

    @pytest.mark.unit
    def test_safe_str_unicode(self):
        """Test _safe_str with unicode characters."""
        unicode_text = "Hello 世界 🌍"
        result = calmweb._safe_str(unicode_text)
        assert result == unicode_text

    @pytest.mark.unit
    def test_safe_str_exception_object(self):
        """Test _safe_str with object that raises exception on str()."""
        class ProblematicObject:
            def __str__(self):
                raise ValueError("Cannot convert to string")

        obj = ProblematicObject()
        result = calmweb._safe_str(obj)
        assert result == "<ProblematicObject object>"

    @pytest.mark.unit
    def test_safe_str_custom_object(self):
        """Test _safe_str with custom object."""
        class CustomObject:
            def __str__(self):
                return "custom representation"

        obj = CustomObject()
        result = calmweb._safe_str(obj)
        assert result == "custom representation"

    @pytest.mark.unit
    def test_safe_str_bytes(self):
        """Test _safe_str with bytes input."""
        test_bytes = b"test bytes"
        result = calmweb._safe_str(test_bytes)
        assert "test bytes" in result


class TestLogFunction:
    """Test the log() function and its thread safety."""

    def setup_method(self):
        """Set up test environment."""
        # Clear log buffer
        calmweb.log_buffer.clear()

    @pytest.mark.unit
    def test_log_simple_message(self, capture_logs):
        """Test logging a simple message."""
        calmweb.log("Test message")

        # Check log buffer
        assert len(calmweb.log_buffer) == 1
        log_entry = calmweb.log_buffer[0]
        assert "Test message" in log_entry
        assert "[" in log_entry and "]" in log_entry  # timestamp

    @pytest.mark.unit
    def test_log_unicode_message(self, capture_logs):
        """Test logging unicode message."""
        unicode_msg = "Unicode test: 你好世界 🌍"
        calmweb.log(unicode_msg)

        assert len(calmweb.log_buffer) == 1
        log_entry = calmweb.log_buffer[0]
        assert "Unicode test" in log_entry

    @pytest.mark.unit
    def test_log_problematic_encoding(self, capture_logs):
        """Test logging with problematic encoding."""
        # Bytes that might cause encoding issues
        problematic_bytes = b'\xff\xfe\x00\x01'
        calmweb.log(problematic_bytes)

        assert len(calmweb.log_buffer) == 1
        # Should not crash and should have some representation

    @pytest.mark.unit
    def test_log_deque_max_size(self, capture_logs):
        """Test that log buffer respects maxlen."""
        # Log more than maxlen messages
        for i in range(1500):  # More than the default 1000
            calmweb.log(f"Message {i}")

        # Should only keep the last 1000
        assert len(calmweb.log_buffer) == 1000
        # Should have the most recent messages
        assert "Message 1499" in calmweb.log_buffer[-1]

    @pytest.mark.unit
    def test_log_thread_safety(self, capture_logs):
        """Test thread safety of log function."""
        num_threads = 10
        messages_per_thread = 50

        def log_messages(thread_id):
            for i in range(messages_per_thread):
                calmweb.log(f"Thread {thread_id} Message {i}")

        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=log_messages, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Should have all messages (within buffer limit)
        total_expected = min(num_threads * messages_per_thread, 1000)
        assert len(calmweb.log_buffer) == total_expected

    @pytest.mark.unit
    @patch('sys.stderr.write')
    @patch('builtins.print')
    def test_log_handles_print_exception(self, mock_print, mock_stderr, capture_logs):
        """Test log function handles print exceptions gracefully."""
        mock_print.side_effect = Exception("Print failed")

        # Should not raise exception
        calmweb.log("Test message")

        # Should still add to buffer
        assert len(calmweb.log_buffer) == 1
        assert "Test message" in calmweb.log_buffer[0]

    @pytest.mark.unit
    def test_log_none_message(self, capture_logs):
        """Test logging None message."""
        calmweb.log(None)

        assert len(calmweb.log_buffer) == 1
        assert "None" in calmweb.log_buffer[0]

    @pytest.mark.unit
    def test_log_exception_object(self, capture_logs):
        """Test logging exception object."""
        try:
            raise ValueError("Test exception")
        except ValueError as e:
            calmweb.log(e)

        assert len(calmweb.log_buffer) == 1
        assert "Test exception" in calmweb.log_buffer[0]


class TestConfigurationParsing:
    """Test configuration file parsing functions."""

    @pytest.mark.unit
    def test_parse_custom_cfg_valid_file(self, sample_custom_cfg):
        """Test parsing a valid custom.cfg file."""
        blocked, whitelist = calmweb.parse_custom_cfg(str(sample_custom_cfg))

        assert "malicious.example.com" in blocked
        assert "scam.site" in blocked
        assert "phishing.net" in blocked

        assert "trusted.example.com" in whitelist
        assert "safe.website.org" in whitelist
        assert "google.com" in whitelist  # *.google.com should become google.com

    @pytest.mark.unit
    def test_parse_custom_cfg_nonexistent_file(self, temp_dir, capture_logs):
        """Test parsing non-existent configuration file."""
        nonexistent_path = str(temp_dir / "nonexistent.cfg")
        blocked, whitelist = calmweb.parse_custom_cfg(nonexistent_path)

        assert len(blocked) == 0
        assert len(whitelist) == 0

    @pytest.mark.unit
    def test_parse_custom_cfg_malformed_file(self, temp_dir, capture_logs):
        """Test parsing malformed configuration file."""
        malformed_cfg = temp_dir / "malformed.cfg"
        content = """[BLOCK]
        malicious.example.com
        [INVALID SECTION
        broken line without section
        [WHITELIST]
        good.example.com
        [OPTIONS]
        invalid_option_line
        block_ip_direct = invalid_value
        block_http_traffic = 1
        """
        malformed_cfg.write_text(content, encoding='utf-8')

        blocked, whitelist = calmweb.parse_custom_cfg(str(malformed_cfg))

        # Should parse what it can
        assert "malicious.example.com" in blocked
        assert "good.example.com" in whitelist

    @pytest.mark.unit
    def test_parse_custom_cfg_options_parsing(self, temp_dir):
        """Test parsing of OPTIONS section."""
        config_file = temp_dir / "options_test.cfg"
        content = """[OPTIONS]
        block_ip_direct = 0
        block_http_traffic = false
        block_http_other_ports = yes
        """
        config_file.write_text(content, encoding='utf-8')

        # Store original values
        orig_ip = calmweb.block_ip_direct
        orig_http = calmweb.block_http_traffic
        orig_ports = calmweb.block_http_other_ports

        try:
            calmweb.parse_custom_cfg(str(config_file))

            assert calmweb.block_ip_direct == False
            assert calmweb.block_http_traffic == False
            assert calmweb.block_http_other_ports == True
        finally:
            # Restore original values
            calmweb.block_ip_direct = orig_ip
            calmweb.block_http_traffic = orig_http
            calmweb.block_http_other_ports = orig_ports

    @pytest.mark.unit
    def test_parse_custom_cfg_comments_and_empty_lines(self, temp_dir):
        """Test that comments and empty lines are handled correctly."""
        config_file = temp_dir / "comments_test.cfg"
        content = """# This is a comment
        [BLOCK]
        # Comment in block section
        malicious.example.com

        # Empty line above
        another-bad.site

        [WHITELIST]
        # Whitelist comment
        good.example.com
        """
        config_file.write_text(content, encoding='utf-8')

        blocked, whitelist = calmweb.parse_custom_cfg(str(config_file))

        assert "malicious.example.com" in blocked
        assert "another-bad.site" in blocked
        assert "good.example.com" in whitelist

    @pytest.mark.unit
    def test_parse_custom_cfg_domain_normalization(self, temp_dir):
        """Test that domains are properly normalized."""
        config_file = temp_dir / "normalization_test.cfg"
        content = """[BLOCK]
        UPPERCASE.EXAMPLE.COM
        .leading-dot.example.com
        trailing-dot.example.com.

        [WHITELIST]
        .LEADING-DOT-WHITELIST.COM
        UPPERCASE-WHITELIST.ORG
        """
        config_file.write_text(content, encoding='utf-8')

        blocked, whitelist = calmweb.parse_custom_cfg(str(config_file))

        # Should be normalized to lowercase and dots stripped
        assert "uppercase.example.com" in blocked
        assert "leading-dot.example.com" in blocked
        assert "trailing-dot.example.com" in blocked

        assert "leading-dot-whitelist.com" in whitelist
        assert "uppercase-whitelist.org" in whitelist

    @pytest.mark.unit
    def test_load_custom_cfg_to_globals(self, sample_custom_cfg, reset_global_state):
        """Test loading configuration to global variables."""
        # Clear globals first
        calmweb.manual_blocked_domains.clear()
        calmweb.whitelisted_domains.clear()

        blocked, whitelist = calmweb.load_custom_cfg_to_globals(str(sample_custom_cfg))

        # Check that globals were updated
        assert "malicious.example.com" in calmweb.manual_blocked_domains
        assert "trusted.example.com" in calmweb.whitelisted_domains

        # Check return values
        assert "malicious.example.com" in blocked
        assert "trusted.example.com" in whitelist

    @pytest.mark.unit
    def test_load_custom_cfg_to_globals_thread_safety(self, sample_custom_cfg, reset_global_state):
        """Test thread safety of load_custom_cfg_to_globals."""
        def load_config():
            calmweb.load_custom_cfg_to_globals(str(sample_custom_cfg))

        # Run multiple threads concurrently
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=load_config)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Should have loaded without errors
        assert len(calmweb.manual_blocked_domains) > 0
        assert len(calmweb.whitelisted_domains) > 0

    @pytest.mark.unit
    def test_get_custom_cfg_path_appdata_priority(self, temp_dir):
        """Test that get_custom_cfg_path prioritizes APPDATA."""
        # Mock USER_CFG_DIR and USER_CFG_PATH
        with patch.object(calmweb, 'USER_CFG_DIR', str(temp_dir)), \
             patch.object(calmweb, 'USER_CFG_PATH', str(temp_dir / "custom.cfg")):

            result = calmweb.get_custom_cfg_path()
            assert result == str(temp_dir / "custom.cfg")

    @pytest.mark.unit
    def test_write_default_custom_cfg(self, temp_dir):
        """Test writing default configuration file."""
        config_path = temp_dir / "default.cfg"
        blocked_set = {"bad1.com", "bad2.com"}
        whitelist_set = {"good1.com", "good2.com"}

        calmweb.write_default_custom_cfg(str(config_path), blocked_set, whitelist_set)

        assert config_path.exists()
        content = config_path.read_text(encoding='utf-8')

        assert "[BLOCK]" in content
        assert "[WHITELIST]" in content
        assert "[OPTIONS]" in content
        assert "bad1.com" in content
        assert "good1.com" in content
        assert "block_ip_direct = 1" in content

    @pytest.mark.unit
    def test_ensure_custom_cfg_exists(self, temp_dir, capture_logs):
        """Test ensure_custom_cfg_exists function."""
        # Mock paths
        with patch.object(calmweb, 'USER_CFG_DIR', str(temp_dir)), \
             patch.object(calmweb, 'USER_CFG_PATH', str(temp_dir / "custom.cfg")):

            blocked_set = {"test.com"}
            whitelist_set = {"safe.com"}

            result_path = calmweb.ensure_custom_cfg_exists(None, blocked_set, whitelist_set)

            assert result_path == str(temp_dir / "custom.cfg")
            assert (temp_dir / "custom.cfg").exists()


class TestThreadSafety:
    """Test thread safety mechanisms."""

    @pytest.mark.unit
    def test_config_lock_prevents_race_conditions(self, reset_global_state):
        """Test that _CONFIG_LOCK prevents race conditions."""
        results = []

        def modify_config(value):
            with calmweb._CONFIG_LOCK:
                # Simulate some processing time
                time.sleep(0.01)
                calmweb.manual_blocked_domains.clear()
                calmweb.manual_blocked_domains.add(f"test{value}.com")
                results.append(len(calmweb.manual_blocked_domains))

        threads = []
        for i in range(10):
            thread = threading.Thread(target=modify_config, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # All results should be 1 (no race conditions)
        assert all(result == 1 for result in results)

    @pytest.mark.unit
    def test_log_lock_thread_safety(self):
        """Test that _LOG_LOCK provides thread safety for logging."""
        def log_many_messages(thread_id):
            for i in range(100):
                calmweb.log(f"Thread {thread_id} Message {i}")

        threads = []
        for i in range(5):
            thread = threading.Thread(target=log_many_messages, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Should not have corrupted buffer
        assert len(calmweb.log_buffer) <= 1000  # Respects maxlen
        # All entries should be properly formatted
        for entry in calmweb.log_buffer:
            assert isinstance(entry, str)
            assert "[" in entry and "]" in entry  # Has timestamp

    @pytest.mark.unit
    def test_shutdown_event_mechanism(self):
        """Test the shutdown event mechanism."""
        # Clear the event
        calmweb._SHUTDOWN_EVENT.clear()
        assert not calmweb._SHUTDOWN_EVENT.is_set()

        # Set the event
        calmweb._SHUTDOWN_EVENT.set()
        assert calmweb._SHUTDOWN_EVENT.is_set()

        # Clear for cleanup
        calmweb._SHUTDOWN_EVENT.clear()

    @pytest.mark.unit
    def test_resolver_loading_event(self):
        """Test the resolver loading event mechanism."""
        # Should start clear
        assert not calmweb._RESOLVER_LOADING.is_set()

        # Test setting and clearing
        calmweb._RESOLVER_LOADING.set()
        assert calmweb._RESOLVER_LOADING.is_set()

        calmweb._RESOLVER_LOADING.clear()
        assert not calmweb._RESOLVER_LOADING.is_set()


class TestRedFlagDomainsAutoUpdate:
    """Test Red Flag Domains automatic update functionality."""

    @pytest.mark.unit
    def test_should_update_red_flag_domains_no_timestamp(self):
        """Test update check when no timestamp file exists."""
        with patch('os.path.exists', return_value=False):
            assert calmweb.should_update_red_flag_domains() == True

    @pytest.mark.unit
    def test_should_update_red_flag_domains_old_timestamp(self):
        """Test update check with old timestamp (>24h)."""
        old_time = datetime.now() - timedelta(hours=25)
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=old_time.isoformat())):
            assert calmweb.should_update_red_flag_domains() == True

    @pytest.mark.unit
    def test_should_update_red_flag_domains_recent_timestamp(self):
        """Test update check with recent timestamp (<24h)."""
        recent_time = datetime.now() - timedelta(hours=12)
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=recent_time.isoformat())):
            assert calmweb.should_update_red_flag_domains() == False

    @pytest.mark.unit
    def test_should_update_red_flag_domains_new_day(self):
        """Test update check for new day even if <24h."""
        yesterday = datetime.now().replace(hour=23, minute=59) - timedelta(days=1)
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=yesterday.isoformat())):
            assert calmweb.should_update_red_flag_domains() == True

    @pytest.mark.unit
    @patch('urllib3.PoolManager')
    def test_download_red_flag_domains_success(self, mock_pool_manager):
        """Test successful download of red.flag.domains."""
        # Mock successful HTTP response
        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = b"0.0.0.0 example-scam.fr\n0.0.0.0 fake-site.fr"
        mock_pool_manager.return_value.request.return_value = mock_response

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(calmweb, 'USER_CFG_DIR', temp_dir), \
                 patch.object(calmweb, 'RED_FLAG_CACHE_PATH', os.path.join(temp_dir, 'red_flag_domains.txt')), \
                 patch.object(calmweb, 'RED_FLAG_TIMESTAMP_PATH', os.path.join(temp_dir, 'red_flag_last_update.txt')):

                result = calmweb.download_red_flag_domains()

                assert result == True
                assert os.path.exists(calmweb.RED_FLAG_CACHE_PATH)
                assert os.path.exists(calmweb.RED_FLAG_TIMESTAMP_PATH)

                # Check file content
                with open(calmweb.RED_FLAG_CACHE_PATH, 'rb') as f:
                    content = f.read()
                    assert b"example-scam.fr" in content

    @pytest.mark.unit
    @patch('urllib3.PoolManager')
    def test_download_red_flag_domains_http_error(self, mock_pool_manager):
        """Test download failure with HTTP error."""
        mock_response = Mock()
        mock_response.status = 404
        mock_pool_manager.return_value.request.return_value = mock_response

        result = calmweb.download_red_flag_domains()
        assert result == False

    @pytest.mark.unit
    @patch('urllib3.PoolManager')
    def test_download_red_flag_domains_network_error(self, mock_pool_manager):
        """Test download failure with network error."""
        mock_pool_manager.return_value.request.side_effect = Exception("Network error")

        result = calmweb.download_red_flag_domains()
        assert result == False

    @pytest.mark.unit
    def test_get_red_flag_domains_path_with_cache(self):
        """Test path retrieval when cache exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_file = os.path.join(temp_dir, 'red_flag_domains.txt')
            with open(cache_file, 'w') as f:
                f.write("test content")

            with patch.object(calmweb, 'RED_FLAG_CACHE_PATH', cache_file), \
                 patch.object(calmweb, 'should_update_red_flag_domains', return_value=False):

                path = calmweb.get_red_flag_domains_path()
                assert path.startswith("file://")
                assert cache_file in path

    @pytest.mark.unit
    def test_get_red_flag_domains_path_fallback(self):
        """Test path retrieval falls back to URL when no cache."""
        with patch.object(calmweb, 'should_update_red_flag_domains', return_value=True), \
             patch.object(calmweb, 'download_red_flag_domains', return_value=False), \
             patch('os.path.exists', return_value=False):

            path = calmweb.get_red_flag_domains_path()
            assert path == "https://dl.red.flag.domains/pihole/red.flag.domains.txt"

    @pytest.mark.unit
    def test_get_blocklist_urls_includes_red_flag_domains(self):
        """Test that get_blocklist_urls includes red.flag.domains."""
        with patch.object(calmweb, 'get_red_flag_domains_path', return_value="file://test.txt"):
            urls = calmweb.get_blocklist_urls()

            assert len(urls) == 5  # 4 original + 1 red.flag.domains
            assert "file://test.txt" in urls
            assert "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts" in urls