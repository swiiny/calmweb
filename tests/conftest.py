"""
Test configuration and shared fixtures for CalmWeb test suite.
"""

import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, Generator, Any
from unittest.mock import Mock, patch, MagicMock

import pytest
from faker import Faker

# Add the program directory to Python path for imports
project_root = Path(__file__).parent.parent
program_dir = project_root / "program"
sys.path.insert(0, str(program_dir))

# Import after path modification
import calmweb

fake = Faker()


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_config_dir(temp_dir: Path) -> Path:
    """Create a mock configuration directory."""
    config_dir = temp_dir / "config"
    config_dir.mkdir(exist_ok=True)
    return config_dir


@pytest.fixture
def sample_custom_cfg(mock_config_dir: Path) -> Path:
    """Create a sample custom.cfg file for testing."""
    config_file = mock_config_dir / "custom.cfg"
    content = """[BLOCK]
malicious.example.com
scam.site
phishing.net

[WHITELIST]
trusted.example.com
safe.website.org
*.google.com

[OPTIONS]
block_ip_direct = 1
block_http_traffic = 1
block_http_other_ports = 1
"""
    config_file.write_text(content, encoding='utf-8')
    return config_file


@pytest.fixture
def mock_blocked_domains() -> set:
    """Sample blocked domains for testing."""
    return {
        "malware.example.com",
        "phishing.test",
        "scam.site",
        "bad-ads.net",
        "tracking.evil"
    }


@pytest.fixture
def mock_whitelisted_domains() -> set:
    """Sample whitelisted domains for testing."""
    return {
        "google.com",
        "github.com",
        "stackoverflow.com",
        "python.org",
        "microsoft.com"
    }


@pytest.fixture
def mock_blocklist_content() -> str:
    """Sample blocklist content in hosts file format."""
    return """# Sample blocklist
0.0.0.0 malware.example.com
127.0.0.1 phishing.test
0.0.0.0 scam.site
# Comment line
badads.net
tracking.evil
"""


@pytest.fixture
def mock_whitelist_content() -> str:
    """Sample whitelist content."""
    return """# Sample whitelist
google.com
github.com
*.microsoft.com
192.168.1.0/24
10.0.0.1
"""


@pytest.fixture
def mock_resolver(mock_blocked_domains: set, mock_whitelisted_domains: set):
    """Create a mock BlocklistResolver for testing."""
    resolver = Mock(spec=calmweb.BlocklistResolver)
    resolver.blocked_domains = mock_blocked_domains.copy()
    resolver.whitelisted_domains_local = mock_whitelisted_domains.copy()
    resolver.whitelisted_networks = set()
    resolver.last_reload = time.time()
    resolver._lock = threading.RLock()
    resolver._loading_lock = threading.RLock()

    # Mock methods
    resolver._is_blocked.side_effect = lambda domain: domain in mock_blocked_domains
    resolver.is_whitelisted.side_effect = lambda domain: domain in mock_whitelisted_domains
    resolver._looks_like_ip.side_effect = calmweb.BlocklistResolver._looks_like_ip
    resolver.maybe_reload_background.return_value = None

    return resolver


@pytest.fixture
def mock_http_request():
    """Create a mock HTTP request for proxy testing."""
    request = Mock()
    request.command = "GET"
    request.path = "http://example.com/test"
    request.request_version = "HTTP/1.1"
    request.headers = {
        "Host": "example.com",
        "User-Agent": "Mozilla/5.0 (Test)",
        "Accept": "text/html",
        "Connection": "keep-alive"
    }
    request.connection = Mock()
    request.connection.recv.return_value = b""
    request.connection.sendall.return_value = None
    request.send_response.return_value = None
    request.send_header.return_value = None
    request.end_headers.return_value = None
    request.send_error.return_value = None
    return request


@pytest.fixture
def mock_socket():
    """Create a mock socket for network testing."""
    sock = Mock()
    sock.recv.return_value = b"test data"
    sock.sendall.return_value = None
    sock.close.return_value = None
    sock.shutdown.return_value = None
    sock.settimeout.return_value = None
    sock.setblocking.return_value = None
    sock.setsockopt.return_value = None
    return sock


@pytest.fixture
def reset_global_state():
    """Reset global state before/after tests."""
    # Store original values
    original_blocked = calmweb.manual_blocked_domains.copy()
    original_whitelisted = calmweb.whitelisted_domains.copy()
    original_block_enabled = calmweb.block_enabled
    original_block_ip_direct = calmweb.block_ip_direct
    original_block_http_traffic = calmweb.block_http_traffic
    original_block_http_other_ports = calmweb.block_http_other_ports
    original_current_resolver = calmweb.current_resolver
    original_log_buffer = list(calmweb.log_buffer)

    yield

    # Restore original values
    calmweb.manual_blocked_domains.clear()
    calmweb.manual_blocked_domains.update(original_blocked)
    calmweb.whitelisted_domains.clear()
    calmweb.whitelisted_domains.update(original_whitelisted)
    calmweb.block_enabled = original_block_enabled
    calmweb.block_ip_direct = original_block_ip_direct
    calmweb.block_http_traffic = original_block_http_traffic
    calmweb.block_http_other_ports = original_block_http_other_ports
    calmweb.current_resolver = original_current_resolver
    calmweb.log_buffer.clear()
    calmweb.log_buffer.extend(original_log_buffer)


@pytest.fixture
def mock_win32_modules():
    """Mock Windows-specific modules for cross-platform testing."""
    with patch.dict('sys.modules', {
        'win32ui': Mock(),
        'win32gui': Mock(),
        'win32con': Mock(),
        'win32com.client': Mock(),
        'winreg': Mock()
    }):
        # Mock win32gui functions
        sys.modules['win32gui'].ExtractIconEx = Mock(return_value=([Mock()], [Mock()]))
        sys.modules['win32gui'].GetDC = Mock(return_value=Mock())
        sys.modules['win32gui'].DrawIconEx = Mock(return_value=True)
        sys.modules['win32gui'].DestroyIcon = Mock(return_value=True)
        sys.modules['win32gui'].ReleaseDC = Mock(return_value=True)

        # Mock win32ui functions
        sys.modules['win32ui'].CreateDCFromHandle = Mock()
        sys.modules['win32ui'].CreateBitmap = Mock()

        # Mock winreg
        sys.modules['winreg'].OpenKey = Mock()
        sys.modules['winreg'].SetValueEx = Mock()
        sys.modules['winreg'].CloseKey = Mock()
        sys.modules['winreg'].HKEY_CURRENT_USER = Mock()
        sys.modules['winreg'].KEY_SET_VALUE = Mock()
        sys.modules['winreg'].REG_DWORD = Mock()
        sys.modules['winreg'].REG_SZ = Mock()

        yield


@pytest.fixture
def mock_subprocess():
    """Mock subprocess calls for testing system commands."""
    with patch('subprocess.run') as mock_run, \
         patch('subprocess.Popen') as mock_popen:
        mock_run.return_value = Mock(returncode=0, stdout=b"", stderr=b"")
        mock_popen.return_value = Mock()
        yield {'run': mock_run, 'popen': mock_popen}


@pytest.fixture
def mock_network_calls():
    """Mock network-related calls for testing without internet."""
    with patch('urllib3.PoolManager') as mock_pool_manager, \
         patch('socket.create_connection') as mock_create_connection, \
         patch('dns.resolver.resolve') as mock_dns_resolve:

        # Mock HTTP responses
        mock_response = Mock()
        mock_response.status = 200
        mock_response.data = b"mock response data"
        mock_pool_manager.return_value.request.return_value = mock_response

        # Mock socket connections
        mock_create_connection.return_value = Mock()

        # Mock DNS resolution
        mock_dns_resolve.return_value = [Mock(address="127.0.0.1")]

        yield {
            'pool_manager': mock_pool_manager,
            'create_connection': mock_create_connection,
            'dns_resolve': mock_dns_resolve
        }


@pytest.fixture
def capture_logs():
    """Capture log messages during tests."""
    # Save original state
    original_buffer = list(calmweb.log_buffer)
    calmweb.log_buffer.clear()

    captured_logs = []
    original_log = calmweb.log

    def capture_log(msg):
        captured_logs.append(str(msg))
        # Also call original log to maintain buffer behavior
        original_log(msg)

    calmweb.log = capture_log

    yield captured_logs

    # Restore
    calmweb.log = original_log
    calmweb.log_buffer.clear()
    calmweb.log_buffer.extend(original_buffer)


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests."""
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# Performance testing helpers
@pytest.fixture
def benchmark_config():
    """Configuration for benchmark tests."""
    return {
        'min_rounds': 5,
        'max_time': 1.0,
        'warmup': True
    }


# Security testing helpers
@pytest.fixture
def malicious_inputs():
    """Collection of malicious input strings for security testing."""
    return [
        # Command injection attempts
        "; rm -rf /",
        "&& del /f /q C:\\*",
        "| cat /etc/passwd",
        "`whoami`",
        "$(id)",

        # Path traversal
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",

        # SQL injection patterns
        "' OR 1=1 --",
        "'; DROP TABLE users; --",
        "1' UNION SELECT * FROM passwords--",

        # XSS patterns
        "<script>alert('xss')</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",

        # Buffer overflow attempts
        "A" * 10000,
        "\x00" * 100,
        "\xff" * 256,

        # Unicode and encoding attacks
        "test\u0000hidden",
        "test\r\nhidden",
        "test%00hidden",

        # Domain/URL attacks
        "http://user:pass@evil.com@good.com/",
        "https://good.com.evil.com/",
        "ftp://localhost:22/",
        "file:///etc/passwd"
    ]


# Platform-specific fixtures
@pytest.fixture
def is_windows():
    """Check if running on Windows."""
    return sys.platform.startswith('win')


@pytest.fixture
def skip_if_not_windows():
    """Skip test if not running on Windows."""
    if not sys.platform.startswith('win'):
        pytest.skip("Windows-only test")


# Helper functions for tests
def create_mock_config_file(path: Path, content: str) -> None:
    """Helper to create a mock configuration file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')


def assert_log_contains(logs: list, message: str) -> bool:
    """Check if logs contain a specific message."""
    return any(message in log for log in logs)


def generate_test_domains(count: int = 10) -> list:
    """Generate test domain names."""
    domains = []
    for _ in range(count):
        domain = f"{fake.word()}.{fake.tld()}"
        domains.append(domain)
    return domains