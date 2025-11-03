# CalmWeb Test Suite

Comprehensive test suite for the CalmWeb proxy/web filter application.

## Overview

The CalmWeb test suite provides thorough testing of all application components including:

- **Unit Tests**: Core functions, utilities, and individual components
- **Integration Tests**: Component interactions and system integration
- **Security Tests**: Input validation, injection prevention, and thread safety
- **Performance Tests**: Load testing, benchmarking, and scalability
- **Windows-Specific Tests**: Platform-specific functionality

## Test Structure

```
tests/
├── __init__.py                 # Test package initialization
├── conftest.py                 # Shared fixtures and configuration
├── test_core_functions.py      # Unit tests for core functions
├── test_blocklist_resolver.py  # BlocklistResolver class tests
├── test_proxy_handler.py       # HTTP proxy handler tests
├── test_security.py            # Security-focused tests
├── test_integration.py         # Integration tests
├── test_windows_specific.py    # Windows-specific tests
├── test_performance.py         # Performance and benchmark tests
├── test_utilities.py           # Test utilities and helpers
└── README.md                   # This file
```

## Running Tests

### Prerequisites

Install test dependencies:

```bash
pip install -r requirements-test.txt
```

### Basic Usage

Run all tests:
```bash
python run_tests.py
```

Or using pytest directly:
```bash
pytest
```

### Test Categories

Run specific test categories:

```bash
# Unit tests only
python run_tests.py --unit

# Security tests only
python run_tests.py --security

# Integration tests only
python run_tests.py --integration

# Performance tests (slow)
python run_tests.py --performance

# Windows-specific tests
python run_tests.py --windows
```

### Coverage Reports

Generate coverage reports:

```bash
# Terminal coverage report
python run_tests.py --coverage

# HTML coverage report
python run_tests.py --coverage-html

# XML coverage report (for CI)
python run_tests.py --coverage-xml
```

### Parallel Execution

Run tests in parallel for faster execution:

```bash
# Use 4 parallel processes
python run_tests.py --parallel 4
```

### Advanced Options

```bash
# Verbose output
python run_tests.py --verbose

# Stop on first failure
python run_tests.py --fail-fast

# Generate JUnit XML report
python run_tests.py --junit-xml report.xml

# Run specific test file
python run_tests.py tests/test_core_functions.py

# Run specific test function
python run_tests.py tests/test_core_functions.py::TestSafeStr::test_safe_str_normal_string
```

## Test Markers

Tests are organized using pytest markers:

- `@pytest.mark.unit` - Unit tests
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.security` - Security-focused tests
- `@pytest.mark.slow` - Slow-running tests
- `@pytest.mark.windows` - Windows-specific tests
- `@pytest.mark.network` - Tests requiring network access

## Key Test Areas

### Core Functions (`test_core_functions.py`)

Tests fundamental utility functions:
- `_safe_str()` function for safe string conversion
- `log()` function with thread safety and deque optimization
- Configuration parsing functions
- Thread safety mechanisms

### BlocklistResolver (`test_blocklist_resolver.py`)

Tests domain blocking and whitelisting:
- Domain blocking logic with subdomain support
- Whitelist priority over blocklist
- IP address detection and blocking
- Network-based whitelisting (CIDR)
- Concurrent access safety

### Proxy Handler (`test_proxy_handler.py`)

Tests HTTP(S) proxy functionality:
- HTTP and HTTPS request handling
- Domain blocking enforcement
- Port restrictions
- Whitelist bypass behavior
- Connection relaying

### Security (`test_security.py`)

Tests security aspects:
- Input validation and sanitization
- Command injection prevention
- Path traversal prevention
- Thread safety under stress
- Resource exhaustion protection

### Integration (`test_integration.py`)

Tests component interactions:
- Proxy server startup and operation
- Configuration lifecycle management
- System integration features
- Error handling across components

### Windows-Specific (`test_windows_specific.py`)

Tests Windows platform features:
- Registry manipulation
- Icon extraction
- Firewall rule management
- Scheduled task creation
- Windows-specific error handling

### Performance (`test_performance.py`)

Tests performance characteristics:
- Large dataset handling
- Concurrent operations
- Memory usage optimization
- Response time benchmarking
- Scalability testing

## Test Utilities

The `test_utilities.py` module provides:

- **MockHTTPHandler**: HTTP server for testing
- **TestDataGenerator**: Generate test data sets
- **TestScenarios**: Common test setup scenarios
- **PerformanceBenchmark**: Performance measurement utilities
- **MockNetworkEnvironment**: Network simulation

## Fixtures

Key fixtures provided in `conftest.py`:

- `temp_dir`: Temporary directory for test files
- `mock_config_dir`: Mock configuration directory
- `sample_custom_cfg`: Sample configuration file
- `mock_resolver`: Mock BlocklistResolver instance
- `reset_global_state`: Reset global variables
- `capture_logs`: Capture log messages during tests
- `mock_win32_modules`: Mock Windows-specific modules

## Security Testing

Security tests focus on:

1. **Input Validation**:
   - Malicious domain names
   - Command injection attempts
   - Path traversal attacks
   - Buffer overflow attempts

2. **Thread Safety**:
   - Concurrent configuration modifications
   - Logging under high load
   - Resolver operations under stress

3. **Error Handling**:
   - Network failures
   - File system errors
   - Registry access errors

## Performance Testing

Performance tests measure:

1. **Domain Lookup Speed**:
   - Large blocklist performance
   - Concurrent lookup operations
   - Memory efficiency

2. **Response Times**:
   - Proxy handler response times
   - Blocking decision speed
   - Configuration reload time

3. **Scalability**:
   - Performance with dataset size
   - Concurrent thread scaling

## Best Practices

### Writing Tests

1. **Use descriptive test names** that explain what is being tested
2. **Follow the AAA pattern**: Arrange, Act, Assert
3. **Use appropriate fixtures** to set up test environment
4. **Mock external dependencies** to ensure test isolation
5. **Test both success and failure cases**
6. **Use parametrized tests** for testing multiple inputs

### Test Organization

1. **Group related tests** in classes
2. **Use appropriate markers** for test categorization
3. **Keep tests independent** and able to run in any order
4. **Use setup/teardown methods** for test preparation

### Mock Usage

1. **Mock external services** and network calls
2. **Mock file system operations** when appropriate
3. **Mock platform-specific functionality** for cross-platform testing
4. **Verify mock interactions** in integration tests

## Continuous Integration

For CI/CD pipelines, use:

```bash
# Fast test suite (excludes slow tests)
python run_tests.py --coverage --junit-xml=test-results.xml

# Full test suite including performance tests
python run_tests.py --coverage --slow --junit-xml=test-results.xml
```

## Troubleshooting

### Common Issues

1. **Tests fail on non-Windows platforms**:
   - Ensure Windows-specific tests are properly marked
   - Use `skip_if_not_windows` fixture

2. **Network tests fail**:
   - Check network connectivity
   - Use `--network` flag for network-dependent tests

3. **Performance tests timeout**:
   - Increase timeout with `--timeout` option
   - Run performance tests separately

4. **Coverage reports incomplete**:
   - Ensure all source files are in the coverage path
   - Check for import errors in test files

### Debug Options

```bash
# Run with maximum verbosity
python run_tests.py -vvv

# Run single test with debug output
pytest -vvs tests/test_core_functions.py::TestSafeStr::test_safe_str_normal_string

# Show test setup/teardown
pytest --setup-show tests/
```

## Contributing

When adding new tests:

1. Follow existing naming conventions
2. Add appropriate markers
3. Update this README if adding new test categories
4. Ensure tests work on both Windows and non-Windows platforms
5. Add performance tests for new performance-critical features