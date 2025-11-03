"""
Test utilities and helper functions for CalmWeb tests.

Includes utilities for:
- Mock HTTP servers for testing
- Test data generation
- Common test scenarios
- Performance benchmarking
"""

import socket
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Any
from unittest.mock import Mock, patch

import pytest

import calmweb


class MockHTTPHandler(BaseHTTPRequestHandler):
    """Mock HTTP handler for testing HTTP requests."""

    responses: Dict[str, Any] = {}

    def do_GET(self):
        """Handle GET requests."""
        path = self.path
        if path in self.responses:
            response_data = self.responses[path]
            self.send_response(response_data.get('status', 200))

            # Send headers
            headers = response_data.get('headers', {})
            for header, value in headers.items():
                self.send_header(header, value)
            self.end_headers()

            # Send body
            body = response_data.get('body', b'')
            if isinstance(body, str):
                body = body.encode('utf-8')
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def do_POST(self):
        """Handle POST requests."""
        self.do_GET()  # Same logic for test purposes

    def log_message(self, format, *args):
        """Suppress logging."""
        pass


@pytest.fixture
def mock_http_server():
    """Create a mock HTTP server for testing."""
    # Find an available port
    sock = socket.socket()
    sock.bind(('localhost', 0))
    port = sock.getsockname()[1]
    sock.close()

    server = HTTPServer(('localhost', port), MockHTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield server, port

    server.shutdown()
    server.server_close()


class TestDataGenerator:
    """Generate test data for various test scenarios."""

    @staticmethod
    def generate_blocklist_content(num_domains: int = 100) -> str:
        """Generate blocklist content in hosts file format."""
        content = "# Generated blocklist for testing\n"
        content += "# This is a test blocklist\n\n"

        for i in range(num_domains):
            # Mix different formats
            if i % 3 == 0:
                content += f"0.0.0.0 malware{i}.example.com\n"
            elif i % 3 == 1:
                content += f"127.0.0.1 phishing{i}.test\n"
            else:
                content += f"badsite{i}.net\n"

            # Add some comments
            if i % 10 == 0:
                content += f"# Block category {i//10}\n"

        return content

    @staticmethod
    def generate_whitelist_content(num_domains: int = 50) -> str:
        """Generate whitelist content."""
        content = "# Generated whitelist for testing\n\n"

        for i in range(num_domains):
            if i % 4 == 0:
                content += f"*.trusted{i}.com\n"
            elif i % 4 == 1:
                content += f"safe{i}.org\n"
            elif i % 4 == 2:
                content += f"192.168.{i % 255}.0/24\n"
            else:
                content += f"10.0.{i % 255}.1\n"

        return content

    @staticmethod
    def generate_malicious_domains(count: int = 20) -> List[str]:
        """Generate list of malicious-looking domain names."""
        malicious_domains = []

        # Common malicious patterns
        prefixes = ['malware', 'phishing', 'scam', 'fake', 'evil', 'bad', 'virus', 'trojan']
        suffixes = ['site', 'download', 'update', 'secure', 'bank', 'paypal', 'amazon']
        tlds = ['com', 'net', 'org', 'info', 'biz', 'tk', 'ml']

        for i in range(count):
            prefix = prefixes[i % len(prefixes)]
            suffix = suffixes[i % len(suffixes)]
            tld = tlds[i % len(tlds)]

            domain = f"{prefix}-{suffix}{i}.{tld}"
            malicious_domains.append(domain)

        return malicious_domains

    @staticmethod
    def generate_trusted_domains(count: int = 20) -> List[str]:
        """Generate list of trusted domain names."""
        trusted_domains = []

        # Common trusted patterns
        bases = ['google', 'microsoft', 'github', 'stackoverflow', 'wikipedia',
                'mozilla', 'python', 'ubuntu', 'redhat', 'amazon']
        tlds = ['com', 'org', 'net', 'edu']

        for i in range(count):
            base = bases[i % len(bases)]
            tld = tlds[i % len(tlds)]

            if i % 3 == 0:
                domain = f"api.{base}.{tld}"
            elif i % 3 == 1:
                domain = f"www.{base}.{tld}"
            else:
                domain = f"{base}.{tld}"

            trusted_domains.append(domain)

        return trusted_domains

    @staticmethod
    def generate_config_content(blocked_domains: List[str],
                              whitelisted_domains: List[str],
                              options: Dict[str, Any] = None) -> str:
        """Generate configuration file content."""
        content = "# Generated configuration for testing\n\n"

        # Block section
        content += "[BLOCK]\n"
        for domain in blocked_domains:
            content += f"{domain}\n"

        content += "\n"

        # Whitelist section
        content += "[WHITELIST]\n"
        for domain in whitelisted_domains:
            content += f"{domain}\n"

        content += "\n"

        # Options section
        content += "[OPTIONS]\n"
        if options:
            for key, value in options.items():
                if isinstance(value, bool):
                    value = "1" if value else "0"
                content += f"{key} = {value}\n"
        else:
            # Default options
            content += "block_ip_direct = 1\n"
            content += "block_http_traffic = 1\n"
            content += "block_http_other_ports = 1\n"

        return content


class TestScenarios:
    """Common test scenarios for CalmWeb functionality."""

    @staticmethod
    def setup_basic_resolver(blocked_domains: List[str] = None,
                           whitelisted_domains: List[str] = None) -> calmweb.BlocklistResolver:
        """Set up a basic resolver for testing."""
        resolver = calmweb.BlocklistResolver([])

        if blocked_domains:
            resolver.blocked_domains = set(blocked_domains)

        if whitelisted_domains:
            resolver.whitelisted_domains_local = set(whitelisted_domains)

        return resolver

    @staticmethod
    def setup_proxy_handler_scenario(target_url: str,
                                   method: str = "GET",
                                   headers: Dict[str, str] = None) -> Mock:
        """Set up a proxy handler test scenario."""
        handler = Mock(spec=calmweb.BlockProxyHandler)
        handler.path = target_url
        handler.command = method
        handler.request_version = "HTTP/1.1"
        handler.headers = headers or {"Host": "example.com"}
        handler.connection = Mock()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.send_error = Mock()

        return handler

    @staticmethod
    def simulate_network_error_scenario(error_type: str = "connection"):
        """Simulate various network error scenarios."""
        if error_type == "connection":
            return ConnectionError("Network unreachable")
        elif error_type == "timeout":
            return TimeoutError("Request timeout")
        elif error_type == "dns":
            return socket.gaierror("Name resolution failed")
        elif error_type == "http":
            response = Mock()
            response.status = 500
            response.data = b"Internal Server Error"
            return response
        else:
            return Exception("Unknown network error")


class PerformanceBenchmark:
    """Performance benchmarking utilities."""

    @staticmethod
    def benchmark_domain_lookup(resolver: calmweb.BlocklistResolver,
                              domains: List[str],
                              iterations: int = 1000) -> Dict[str, float]:
        """Benchmark domain lookup performance."""
        import time

        results = {}

        # Benchmark _is_blocked
        start_time = time.time()
        for _ in range(iterations):
            for domain in domains:
                resolver._is_blocked(domain)
        blocked_time = time.time() - start_time

        # Benchmark is_whitelisted
        start_time = time.time()
        for _ in range(iterations):
            for domain in domains:
                resolver.is_whitelisted(domain)
        whitelist_time = time.time() - start_time

        # Benchmark _looks_like_ip
        start_time = time.time()
        for _ in range(iterations):
            for domain in domains:
                resolver._looks_like_ip(domain)
        ip_check_time = time.time() - start_time

        results = {
            'blocked_check_time': blocked_time,
            'whitelist_check_time': whitelist_time,
            'ip_check_time': ip_check_time,
            'total_operations': iterations * len(domains),
            'avg_blocked_check': blocked_time / (iterations * len(domains)),
            'avg_whitelist_check': whitelist_time / (iterations * len(domains)),
            'avg_ip_check': ip_check_time / (iterations * len(domains))
        }

        return results

    @staticmethod
    def benchmark_logging_performance(message_count: int = 10000) -> Dict[str, float]:
        """Benchmark logging performance."""
        import time

        # Clear existing log buffer
        original_buffer = list(calmweb.log_buffer)
        calmweb.log_buffer.clear()

        try:
            start_time = time.time()

            for i in range(message_count):
                calmweb.log(f"Benchmark message {i}")

            end_time = time.time()

            total_time = end_time - start_time

            return {
                'total_time': total_time,
                'messages_logged': message_count,
                'avg_time_per_message': total_time / message_count,
                'messages_per_second': message_count / total_time,
                'buffer_size': len(calmweb.log_buffer)
            }

        finally:
            # Restore original buffer
            calmweb.log_buffer.clear()
            calmweb.log_buffer.extend(original_buffer)

    @staticmethod
    def benchmark_config_parsing(config_content: str,
                                iterations: int = 100) -> Dict[str, float]:
        """Benchmark configuration parsing performance."""
        import time
        import tempfile
        import os

        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.cfg') as f:
            f.write(config_content)
            temp_path = f.name

        try:
            start_time = time.time()

            for _ in range(iterations):
                calmweb.parse_custom_cfg(temp_path)

            end_time = time.time()

            total_time = end_time - start_time

            return {
                'total_time': total_time,
                'iterations': iterations,
                'avg_time_per_parse': total_time / iterations,
                'parses_per_second': iterations / total_time,
                'config_size_bytes': len(config_content.encode('utf-8'))
            }

        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_path)
            except Exception:
                pass


class MockNetworkEnvironment:
    """Mock network environment for testing."""

    def __init__(self):
        self.blocked_responses = {}
        self.whitelist_responses = {}
        self.network_errors = {}

    def add_blocklist_response(self, url: str, content: str, status: int = 200):
        """Add a mock blocklist response."""
        self.blocked_responses[url] = {
            'status': status,
            'content': content,
            'headers': {'Content-Type': 'text/plain'}
        }

    def add_whitelist_response(self, url: str, content: str, status: int = 200):
        """Add a mock whitelist response."""
        self.whitelist_responses[url] = {
            'status': status,
            'content': content,
            'headers': {'Content-Type': 'text/plain'}
        }

    def add_network_error(self, url: str, error: Exception):
        """Add a network error for a specific URL."""
        self.network_errors[url] = error

    def create_mock_pool_manager(self):
        """Create a mock urllib3.PoolManager."""
        def mock_request(method, url, **kwargs):
            if url in self.network_errors:
                raise self.network_errors[url]

            response_data = None
            if url in self.blocked_responses:
                response_data = self.blocked_responses[url]
            elif url in self.whitelist_responses:
                response_data = self.whitelist_responses[url]

            if response_data:
                mock_response = Mock()
                mock_response.status = response_data['status']
                mock_response.data = response_data['content'].encode('utf-8')
                return mock_response
            else:
                # Default 404 response
                mock_response = Mock()
                mock_response.status = 404
                mock_response.data = b"Not Found"
                return mock_response

        mock_pool = Mock()
        mock_pool.request = mock_request
        return mock_pool


# Test utility fixtures
@pytest.fixture
def test_data_generator():
    """Provide test data generator."""
    return TestDataGenerator()


@pytest.fixture
def test_scenarios():
    """Provide test scenarios."""
    return TestScenarios()


@pytest.fixture
def performance_benchmark():
    """Provide performance benchmark utilities."""
    return PerformanceBenchmark()


@pytest.fixture
def mock_network_env():
    """Provide mock network environment."""
    return MockNetworkEnvironment()


# Helper functions for common assertions
def assert_domain_blocked(resolver: calmweb.BlocklistResolver, domain: str):
    """Assert that a domain is blocked."""
    assert resolver._is_blocked(domain) == True, f"Domain {domain} should be blocked"


def assert_domain_allowed(resolver: calmweb.BlocklistResolver, domain: str):
    """Assert that a domain is allowed."""
    assert resolver._is_blocked(domain) == False, f"Domain {domain} should be allowed"


def assert_domain_whitelisted(resolver: calmweb.BlocklistResolver, domain: str):
    """Assert that a domain is whitelisted."""
    assert resolver.is_whitelisted(domain) == True, f"Domain {domain} should be whitelisted"


def assert_proxy_blocks_request(handler_mock: Mock, expected_error_code: int = 403):
    """Assert that proxy handler blocks a request."""
    handler_mock.send_error.assert_called()
    call_args = handler_mock.send_error.call_args[0]
    assert call_args[0] == expected_error_code


def assert_proxy_allows_request(handler_mock: Mock):
    """Assert that proxy handler allows a request."""
    # Should call send_response with 200 or proceed to connection
    assert not handler_mock.send_error.called or \
           handler_mock.send_response.called


def assert_log_contains_message(logs: List[str], message: str):
    """Assert that log contains a specific message."""
    found = any(message in log for log in logs)
    assert found, f"Log should contain message: {message}"


def assert_config_loaded_correctly(blocked_expected: set, whitelist_expected: set):
    """Assert that configuration was loaded correctly."""
    assert blocked_expected.issubset(calmweb.manual_blocked_domains), \
           "Expected blocked domains not found in global state"
    assert whitelist_expected.issubset(calmweb.whitelisted_domains), \
           "Expected whitelisted domains not found in global state"