"""
Unit tests for HTTP(S) Proxy Handler functionality.

Tests the BlockProxyHandler class including:
- HTTP and HTTPS request handling
- Domain blocking and whitelisting
- Port restrictions
- Connection relaying
"""

import socket
from unittest.mock import Mock, patch, MagicMock
from urllib.parse import urlparse

import pytest

import calmweb


class TestBlockProxyHandler:
    """Test the BlockProxyHandler class."""

    def setup_method(self):
        """Set up test environment."""
        # Reset global state
        calmweb.block_enabled = True
        calmweb.block_ip_direct = True
        calmweb.block_http_traffic = True
        calmweb.block_http_other_ports = True
        calmweb.current_resolver = None

    @pytest.fixture
    def mock_handler(self, mock_http_request):
        """Create a mock BlockProxyHandler instance."""
        handler = calmweb.BlockProxyHandler(
            request=mock_http_request,
            client_address=("127.0.0.1", 12345),
            server=Mock()
        )
        handler.connection = Mock()
        handler.rfile = Mock()
        handler.wfile = Mock()
        return handler

    @pytest.mark.unit
    def test_extract_hostname_from_path_http_url(self):
        """Test hostname extraction from HTTP URL."""
        handler = calmweb.BlockProxyHandler
        hostname = handler._extract_hostname_from_path(
            None, "http://example.com/path/to/resource"
        )
        assert hostname == "example.com"

    @pytest.mark.unit
    def test_extract_hostname_from_path_https_url(self):
        """Test hostname extraction from HTTPS URL."""
        handler = calmweb.BlockProxyHandler
        hostname = handler._extract_hostname_from_path(
            None, "https://secure.example.com/api/v1/data"
        )
        assert hostname == "secure.example.com"

    @pytest.mark.unit
    def test_extract_hostname_from_path_with_port(self):
        """Test hostname extraction from URL with port."""
        handler = calmweb.BlockProxyHandler
        hostname = handler._extract_hostname_from_path(
            None, "http://example.com:8080/path"
        )
        assert hostname == "example.com"

    @pytest.mark.unit
    def test_extract_hostname_from_path_invalid_url(self):
        """Test hostname extraction from invalid URL."""
        handler = calmweb.BlockProxyHandler
        hostname = handler._extract_hostname_from_path(
            None, "not-a-valid-url"
        )
        assert hostname is None

    @pytest.mark.unit
    @patch('socket.create_connection')
    def test_do_connect_allowed_domain(self, mock_create_connection, mock_resolver):
        """Test CONNECT method with allowed domain."""
        mock_create_connection.return_value = Mock()
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = False

        # Create handler mock
        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "example.com:443"
        handler.connection = Mock()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()

        # Call the actual method
        calmweb.BlockProxyHandler.do_CONNECT(handler)

        handler.send_response.assert_called_with(200, "Connection Established")
        mock_create_connection.assert_called_once()

    @pytest.mark.unit
    def test_do_connect_blocked_domain(self, mock_resolver):
        """Test CONNECT method with blocked domain."""
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = True

        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "malware.example.com:443"
        handler.send_error = Mock()

        calmweb.BlockProxyHandler.do_CONNECT(handler)

        handler.send_error.assert_called_with(403, "Bloqué par sécurité")

    @pytest.mark.unit
    def test_do_connect_whitelisted_domain_bypass(self, mock_resolver):
        """Test CONNECT method with whitelisted domain bypasses all restrictions."""
        calmweb.current_resolver = mock_resolver
        mock_resolver.is_whitelisted.return_value = True
        mock_resolver._is_blocked.return_value = True  # Would normally be blocked

        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "trusted.example.com:8080"  # Non-standard port
        handler.connection = Mock()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()

        with patch('socket.create_connection') as mock_create_connection:
            mock_create_connection.return_value = Mock()
            with patch('calmweb.full_duplex_relay') as mock_relay:
                calmweb.BlockProxyHandler.do_CONNECT(handler)

        # Should allow connection despite being "blocked" and non-standard port
        handler.send_response.assert_called_with(200, "Connection Established")

    @pytest.mark.unit
    def test_do_connect_non_standard_port_blocked(self, mock_resolver):
        """Test CONNECT method blocks non-standard ports when configured."""
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = False
        mock_resolver.is_whitelisted.return_value = False
        calmweb.block_http_other_ports = True

        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "example.com:9999"  # Non-standard port
        handler.send_error = Mock()

        calmweb.BlockProxyHandler.do_CONNECT(handler)

        handler.send_error.assert_called_with(403, "port non standard bloqué par sécurité")

    @pytest.mark.unit
    def test_do_connect_voip_ports_allowed(self, mock_resolver):
        """Test CONNECT method allows VOIP ports."""
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = False
        mock_resolver.is_whitelisted.return_value = False
        calmweb.block_http_other_ports = True

        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "voip.example.com:5060"  # SIP port
        handler.connection = Mock()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()

        with patch('socket.create_connection') as mock_create_connection:
            mock_create_connection.return_value = Mock()
            with patch('calmweb.full_duplex_relay') as mock_relay:
                calmweb.BlockProxyHandler.do_CONNECT(handler)

        # Should allow VOIP port
        handler.send_response.assert_called_with(200, "Connection Established")

    @pytest.mark.unit
    def test_handle_http_method_blocked_domain(self, mock_resolver):
        """Test HTTP method handling with blocked domain."""
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = True
        mock_resolver.is_whitelisted.return_value = False

        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "http://malware.example.com/malicious"
        handler.command = "GET"
        handler.headers = {"Host": "malware.example.com"}
        handler.send_error = Mock()

        calmweb.BlockProxyHandler._handle_http_method(handler)

        handler.send_error.assert_called_with(403, "Bloqué par sécurité")

    @pytest.mark.unit
    def test_handle_http_method_whitelisted_bypass(self, mock_resolver):
        """Test HTTP method handling with whitelisted domain bypasses restrictions."""
        calmweb.current_resolver = mock_resolver
        mock_resolver.is_whitelisted.return_value = True
        mock_resolver._is_blocked.return_value = True  # Would be blocked
        calmweb.block_http_traffic = True  # HTTP would be blocked

        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "http://trusted.example.com/api"  # HTTP (normally blocked)
        handler.command = "GET"
        handler.request_version = "HTTP/1.1"
        handler.headers = {"Host": "trusted.example.com"}
        handler.connection = Mock()

        with patch('socket.create_connection') as mock_create_connection:
            mock_create_connection.return_value = Mock()
            with patch('calmweb.full_duplex_relay') as mock_relay:
                calmweb.BlockProxyHandler._handle_http_method(handler)

        # Should proceed to connection creation (not call send_error)
        mock_create_connection.assert_called_once()

    @pytest.mark.unit
    def test_handle_http_method_http_traffic_blocked(self, mock_resolver):
        """Test HTTP method blocks HTTP traffic when configured."""
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = False
        mock_resolver.is_whitelisted.return_value = False
        calmweb.block_http_traffic = True

        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "http://example.com/insecure"  # HTTP
        handler.command = "GET"
        handler.headers = {"Host": "example.com"}
        handler.send_error = Mock()

        calmweb.BlockProxyHandler._handle_http_method(handler)

        handler.send_error.assert_called_with(403, "Bloqué HTTP par sécurité")

    @pytest.mark.unit
    def test_handle_http_method_non_standard_port_blocked(self, mock_resolver):
        """Test HTTP method blocks non-standard ports when configured."""
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = False
        mock_resolver.is_whitelisted.return_value = False
        calmweb.block_http_other_ports = True

        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "https://example.com:8443/api"  # Non-standard HTTPS port
        handler.command = "GET"
        handler.headers = {"Host": "example.com:8443"}
        handler.send_error = Mock()

        calmweb.BlockProxyHandler._handle_http_method(handler)

        handler.send_error.assert_called_with(403, "port non standard bloqué par sécurité")

    @pytest.mark.unit
    def test_handle_http_method_host_header_parsing(self, mock_resolver):
        """Test HTTP method correctly parses Host header."""
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = False
        mock_resolver.is_whitelisted.return_value = False

        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "/relative/path"  # Relative path
        handler.command = "GET"
        handler.request_version = "HTTP/1.1"
        handler.headers = {"Host": "example.com:8080"}
        handler.connection = Mock()

        with patch('socket.create_connection') as mock_create_connection:
            mock_create_connection.return_value = Mock()
            with patch('calmweb.full_duplex_relay') as mock_relay:
                calmweb.BlockProxyHandler._handle_http_method(handler)

        # Should extract target from Host header
        mock_create_connection.assert_called_with(("example.com", 8080), timeout=10)

    @pytest.mark.unit
    def test_handle_http_method_header_forwarding(self, mock_resolver):
        """Test HTTP method correctly forwards headers."""
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = False
        mock_resolver.is_whitelisted.return_value = False

        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "https://example.com/api"
        handler.command = "POST"
        handler.request_version = "HTTP/1.1"
        handler.headers = {
            "Host": "example.com",
            "User-Agent": "CalmWeb-Test/1.0",
            "Content-Type": "application/json",
            "Proxy-Connection": "keep-alive",  # Should be filtered
            "Authorization": "Bearer token123"
        }
        handler.connection = Mock()

        mock_socket = Mock()
        with patch('socket.create_connection', return_value=mock_socket):
            with patch('calmweb.full_duplex_relay') as mock_relay:
                calmweb.BlockProxyHandler._handle_http_method(handler)

        # Verify socket.sendall was called with properly formatted request
        assert mock_socket.sendall.called
        sent_data = mock_socket.sendall.call_args[0][0]
        sent_text = sent_data.decode('utf-8')

        # Check request line
        assert "POST /api HTTP/1.1" in sent_text
        assert "Host: example.com" in sent_text
        assert "User-Agent: CalmWeb-Test/1.0" in sent_text
        assert "Content-Type: application/json" in sent_text
        assert "Authorization: Bearer token123" in sent_text

        # Check that hop-by-hop headers are filtered
        assert "Proxy-Connection" not in sent_text
        assert "Connection: close" in sent_text

    @pytest.mark.unit
    def test_http_methods_delegation(self):
        """Test that HTTP methods delegate to _handle_http_method."""
        handler = Mock(spec=calmweb.BlockProxyHandler)

        with patch.object(calmweb.BlockProxyHandler, '_handle_http_method') as mock_handle:
            calmweb.BlockProxyHandler.do_GET(handler)
            calmweb.BlockProxyHandler.do_POST(handler)
            calmweb.BlockProxyHandler.do_PUT(handler)
            calmweb.BlockProxyHandler.do_DELETE(handler)
            calmweb.BlockProxyHandler.do_HEAD(handler)

        assert mock_handle.call_count == 5

    @pytest.mark.unit
    def test_log_message_silenced(self):
        """Test that log_message is silenced (returns without action)."""
        handler = Mock(spec=calmweb.BlockProxyHandler)
        result = calmweb.BlockProxyHandler.log_message(handler, "format", "arg1", "arg2")
        assert result is None

    @pytest.mark.unit
    def test_proxy_handler_voip_allowed_ports(self):
        """Test VOIP_ALLOWED_PORTS contains expected ports."""
        expected_ports = {80, 443, 3478, 5060, 5061}
        assert calmweb.BlockProxyHandler.VOIP_ALLOWED_PORTS == expected_ports

    @pytest.mark.unit
    def test_proxy_handler_timeout_configuration(self):
        """Test proxy handler timeout is configured."""
        assert hasattr(calmweb.BlockProxyHandler, 'timeout')
        assert isinstance(calmweb.BlockProxyHandler.timeout, int)
        assert calmweb.BlockProxyHandler.timeout > 0

    @pytest.mark.unit
    def test_proxy_handler_protocol_version(self):
        """Test proxy handler uses HTTP/1.1."""
        assert calmweb.BlockProxyHandler.protocol_version == "HTTP/1.1"


class TestProxyHandlerIntegration:
    """Integration tests for proxy handler with full request flow."""

    def setup_method(self):
        """Set up test environment."""
        calmweb.block_enabled = True
        calmweb.block_ip_direct = True
        calmweb.block_http_traffic = True
        calmweb.block_http_other_ports = True

    @pytest.mark.integration
    @patch('socket.create_connection')
    def test_full_http_request_flow(self, mock_create_connection, mock_resolver):
        """Test complete HTTP request handling flow."""
        # Set up resolver
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = False
        mock_resolver.is_whitelisted.return_value = False

        # Mock socket
        mock_socket = Mock()
        mock_create_connection.return_value = mock_socket

        # Create handler
        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "https://api.example.com/data"
        handler.command = "GET"
        handler.request_version = "HTTP/1.1"
        handler.headers = {
            "Host": "api.example.com",
            "User-Agent": "TestClient/1.0",
            "Accept": "application/json"
        }
        handler.connection = Mock()

        with patch('calmweb.full_duplex_relay') as mock_relay:
            calmweb.BlockProxyHandler._handle_http_method(handler)

        # Verify flow
        mock_create_connection.assert_called_once_with(("api.example.com", 443), timeout=10)
        mock_socket.sendall.assert_called_once()
        mock_relay.assert_called_once_with(handler.connection, mock_socket)

    @pytest.mark.integration
    def test_blocked_domain_full_flow(self, mock_resolver, capture_logs):
        """Test complete flow with blocked domain."""
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = True
        mock_resolver.is_whitelisted.return_value = False

        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "https://malware.evil.com/download"
        handler.command = "GET"
        handler.headers = {"Host": "malware.evil.com"}
        handler.send_error = Mock()

        calmweb.BlockProxyHandler._handle_http_method(handler)

        handler.send_error.assert_called_with(403, "Bloqué par sécurité")

    @pytest.mark.integration
    def test_whitelisted_domain_bypass_all_restrictions(self, mock_resolver):
        """Test whitelisted domain bypasses all restrictions."""
        calmweb.current_resolver = mock_resolver
        mock_resolver.is_whitelisted.return_value = True
        mock_resolver._is_blocked.return_value = True  # Would be blocked
        calmweb.block_http_traffic = True  # HTTP blocked
        calmweb.block_http_other_ports = True  # Non-standard ports blocked

        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "http://trusted.example.com:8080/api"  # HTTP + non-standard port
        handler.command = "POST"
        handler.request_version = "HTTP/1.1"
        handler.headers = {"Host": "trusted.example.com:8080"}
        handler.connection = Mock()

        with patch('socket.create_connection') as mock_create_connection:
            mock_create_connection.return_value = Mock()
            with patch('calmweb.full_duplex_relay') as mock_relay:
                calmweb.BlockProxyHandler._handle_http_method(handler)

        # Should proceed despite all restrictions
        mock_create_connection.assert_called_once()

    @pytest.mark.integration
    def test_ip_address_blocking(self, mock_resolver):
        """Test IP address blocking functionality."""
        calmweb.current_resolver = mock_resolver
        mock_resolver._is_blocked.return_value = True  # IP should be blocked
        mock_resolver.is_whitelisted.return_value = False
        calmweb.block_ip_direct = True

        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = "192.168.1.100:443"
        handler.send_error = Mock()

        calmweb.BlockProxyHandler.do_CONNECT(handler)

        handler.send_error.assert_called_with(403, "Bloqué par sécurité")

    @pytest.mark.integration
    def test_error_handling_in_proxy_flow(self, mock_resolver, capture_logs):
        """Test error handling during proxy operations."""
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
        with patch('socket.create_connection', side_effect=Exception("Connection failed")):
            calmweb.BlockProxyHandler._handle_http_method(handler)

        # Should handle error gracefully
        handler.send_error.assert_called_with(502, "Bad Gateway")