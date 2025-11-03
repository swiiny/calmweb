"""
Performance tests for CalmWeb.

Tests performance aspects including:
- Large dataset handling
- Concurrent operations
- Memory usage
- Response times
"""

import threading
import time
from unittest.mock import Mock, patch

import pytest

import calmweb
from tests.test_utilities import PerformanceBenchmark, TestDataGenerator


class TestPerformanceBasics:
    """Basic performance tests."""

    @pytest.mark.slow
    def test_large_blocklist_performance(self, benchmark_config):
        """Test performance with large blocklists."""
        # Create resolver with large blocklist
        resolver = calmweb.BlocklistResolver([])

        # Generate large domain set
        large_domains = set()
        for i in range(100000):  # 100k domains
            large_domains.add(f"domain{i}.example.com")

        resolver.blocked_domains = large_domains

        # Benchmark lookups
        test_domains = [f"domain{i * 1000}.example.com" for i in range(100)]

        start_time = time.time()
        for domain in test_domains:
            result = resolver._is_blocked(domain)
            assert result == True  # Should be found

        end_time = time.time()
        lookup_time = end_time - start_time

        # Should complete lookups quickly (less than 100ms for 100 lookups in 100k set)
        assert lookup_time < 0.1, f"Lookup took too long: {lookup_time}s"

    @pytest.mark.slow
    def test_concurrent_domain_lookups(self):
        """Test concurrent domain lookup performance."""
        resolver = calmweb.BlocklistResolver([])
        resolver.blocked_domains = {f"blocked{i}.com" for i in range(10000)}

        results = []
        errors = []

        def lookup_worker(thread_id):
            try:
                for i in range(1000):
                    domain = f"blocked{i}.com"
                    result = resolver._is_blocked(domain)
                    results.append(result)
            except Exception as e:
                errors.append(str(e))

        # Run concurrent lookups
        start_time = time.time()

        threads = []
        for i in range(20):  # 20 concurrent threads
            thread = threading.Thread(target=lookup_worker, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        end_time = time.time()
        total_time = end_time - start_time

        # Should complete without errors
        assert len(errors) == 0, f"Errors occurred: {errors}"

        # Should have all results
        assert len(results) == 20 * 1000

        # Should complete within reasonable time (5 seconds for 20k lookups)
        assert total_time < 5.0, f"Concurrent lookups took too long: {total_time}s"

    @pytest.mark.slow
    def test_logging_performance_under_load(self):
        """Test logging performance under heavy load."""
        # Clear log buffer
        original_buffer = list(calmweb.log_buffer)
        calmweb.log_buffer.clear()

        try:
            def log_worker(thread_id):
                for i in range(1000):
                    calmweb.log(f"Thread {thread_id} message {i}")

            start_time = time.time()

            threads = []
            for i in range(10):
                thread = threading.Thread(target=log_worker, args=(i,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            end_time = time.time()
            total_time = end_time - start_time

            # Should complete within reasonable time
            assert total_time < 2.0, f"Logging took too long: {total_time}s"

            # Buffer should respect size limit
            assert len(calmweb.log_buffer) <= 1000

        finally:
            # Restore original buffer
            calmweb.log_buffer.clear()
            calmweb.log_buffer.extend(original_buffer)

    @pytest.mark.slow
    def test_config_parsing_performance(self, temp_dir):
        """Test configuration parsing performance with large files."""
        # Generate large config file
        generator = TestDataGenerator()
        blocked_domains = [f"blocked{i}.example.com" for i in range(50000)]
        whitelisted_domains = [f"safe{i}.example.com" for i in range(10000)]

        config_content = generator.generate_config_content(
            blocked_domains, whitelisted_domains
        )

        config_file = temp_dir / "large_config.cfg"
        config_file.write_text(config_content, encoding='utf-8')

        # Benchmark parsing
        start_time = time.time()

        for _ in range(10):  # Parse multiple times
            blocked, whitelist = calmweb.parse_custom_cfg(str(config_file))

        end_time = time.time()
        total_time = end_time - start_time

        # Should parse correctly
        assert len(blocked) == 50000
        assert len(whitelist) == 10000

        # Should complete within reasonable time (less than 5 seconds for 10 parses)
        assert total_time < 5.0, f"Config parsing took too long: {total_time}s"


class TestMemoryPerformance:
    """Memory usage performance tests."""

    @pytest.mark.slow
    def test_log_buffer_memory_limit(self):
        """Test that log buffer doesn't consume excessive memory."""
        import sys

        # Clear log buffer
        original_buffer = list(calmweb.log_buffer)
        calmweb.log_buffer.clear()

        try:
            # Log many large messages
            large_message = "A" * 10000  # 10KB message
            for i in range(2000):  # Try to log more than buffer limit
                calmweb.log(f"{large_message} message {i}")

            # Buffer should respect size limit
            assert len(calmweb.log_buffer) <= 1000

            # Calculate approximate memory usage
            total_chars = sum(len(entry) for entry in calmweb.log_buffer)
            # Should be reasonable size (less than 100MB)
            assert total_chars < 100 * 1024 * 1024

        finally:
            calmweb.log_buffer.clear()
            calmweb.log_buffer.extend(original_buffer)

    @pytest.mark.slow
    def test_domain_set_memory_efficiency(self):
        """Test memory efficiency of domain sets."""
        resolver = calmweb.BlocklistResolver([])

        # Add many domains
        num_domains = 500000  # 500k domains
        for i in range(num_domains):
            resolver.blocked_domains.add(f"domain{i}.example.com")

        # Should handle large sets efficiently
        assert len(resolver.blocked_domains) == num_domains

        # Lookups should still be fast
        start_time = time.time()
        result1 = resolver._is_blocked("domain100000.example.com")
        result2 = resolver._is_blocked("nonexistent.example.com")
        end_time = time.time()

        assert result1 == True
        assert result2 == False
        assert (end_time - start_time) < 0.001  # Less than 1ms

    @pytest.mark.slow
    def test_concurrent_memory_usage(self):
        """Test memory usage under concurrent operations."""
        resolver = calmweb.BlocklistResolver([])

        def memory_stress_worker(thread_id):
            # Each thread works with its own domain set
            local_domains = set()
            for i in range(10000):
                local_domains.add(f"thread{thread_id}-domain{i}.com")

            # Simulate domain operations
            for domain in local_domains:
                resolver._is_blocked(domain)
                resolver.is_whitelisted(domain)

        threads = []
        for i in range(50):  # 50 threads
            thread = threading.Thread(target=memory_stress_worker, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Should complete without memory errors


class TestResponseTimePerformance:
    """Response time performance tests."""

    @pytest.mark.slow
    @patch('socket.create_connection')
    def test_proxy_handler_response_time(self, mock_create_connection, mock_resolver):
        """Test proxy handler response times."""
        mock_socket = Mock()
        mock_create_connection.return_value = mock_socket

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

        # Benchmark response time
        response_times = []

        with patch('calmweb.full_duplex_relay') as mock_relay:
            for _ in range(100):
                start_time = time.time()
                calmweb.BlockProxyHandler._handle_http_method(handler)
                end_time = time.time()
                response_times.append(end_time - start_time)

        # Calculate statistics
        avg_response_time = sum(response_times) / len(response_times)
        max_response_time = max(response_times)

        # Should have fast response times
        assert avg_response_time < 0.01, f"Average response time too slow: {avg_response_time}s"
        assert max_response_time < 0.05, f"Max response time too slow: {max_response_time}s"

    @pytest.mark.slow
    def test_domain_blocking_decision_time(self):
        """Test time to make blocking decisions."""
        resolver = calmweb.BlocklistResolver([])

        # Set up test data
        resolver.blocked_domains = {f"malware{i}.com" for i in range(100000)}
        resolver.whitelisted_domains_local = {f"safe{i}.com" for i in range(10000)}

        test_domains = [
            "malware50000.com",  # Blocked
            "safe5000.com",      # Whitelisted
            "unknown.com",       # Unknown
            "192.168.1.1",      # IP address
        ]

        # Benchmark decision times
        decision_times = []

        for _ in range(1000):
            for domain in test_domains:
                start_time = time.time()
                resolver._is_blocked(domain)
                end_time = time.time()
                decision_times.append(end_time - start_time)

        avg_decision_time = sum(decision_times) / len(decision_times)
        max_decision_time = max(decision_times)

        # Should make fast blocking decisions
        assert avg_decision_time < 0.0001, f"Average decision time too slow: {avg_decision_time}s"
        assert max_decision_time < 0.001, f"Max decision time too slow: {max_decision_time}s"

    @pytest.mark.slow
    def test_configuration_reload_time(self, temp_dir):
        """Test configuration reload performance."""
        # Create large config file
        generator = TestDataGenerator()
        blocked_domains = [f"blocked{i}.com" for i in range(10000)]
        whitelisted_domains = [f"safe{i}.com" for i in range(5000)]

        config_content = generator.generate_config_content(
            blocked_domains, whitelisted_domains
        )

        config_file = temp_dir / "reload_test.cfg"
        config_file.write_text(config_content, encoding='utf-8')

        # Benchmark reload times
        reload_times = []

        for _ in range(10):
            start_time = time.time()
            calmweb.load_custom_cfg_to_globals(str(config_file))
            end_time = time.time()
            reload_times.append(end_time - start_time)

        avg_reload_time = sum(reload_times) / len(reload_times)
        max_reload_time = max(reload_times)

        # Should reload quickly
        assert avg_reload_time < 0.5, f"Average reload time too slow: {avg_reload_time}s"
        assert max_reload_time < 1.0, f"Max reload time too slow: {max_reload_time}s"


class TestScalabilityPerformance:
    """Scalability performance tests."""

    @pytest.mark.slow
    def test_scaling_with_blocklist_size(self):
        """Test performance scaling with blocklist size."""
        resolver = calmweb.BlocklistResolver([])

        sizes = [1000, 10000, 100000, 500000]
        lookup_times = []

        for size in sizes:
            # Create blocklist of given size
            resolver.blocked_domains = {f"domain{i}.com" for i in range(size)}

            # Test lookup time
            test_domain = f"domain{size//2}.com"  # Domain in middle of set

            start_time = time.time()
            for _ in range(1000):  # 1000 lookups
                resolver._is_blocked(test_domain)
            end_time = time.time()

            lookup_time = end_time - start_time
            lookup_times.append(lookup_time)

        # Lookup time should scale reasonably (not exponentially)
        # Each size is 10x larger, but time shouldn't increase by 10x
        for i in range(1, len(lookup_times)):
            ratio = lookup_times[i] / lookup_times[i-1]
            assert ratio < 5, f"Performance degraded too much: {ratio}x slower"

    @pytest.mark.slow
    def test_scaling_with_concurrent_threads(self):
        """Test performance scaling with number of concurrent threads."""
        resolver = calmweb.BlocklistResolver([])
        resolver.blocked_domains = {f"domain{i}.com" for i in range(50000)}

        thread_counts = [1, 5, 10, 20, 50]
        completion_times = []

        for thread_count in thread_counts:
            def worker():
                for i in range(1000):
                    resolver._is_blocked(f"domain{i}.com")

            start_time = time.time()

            threads = []
            for _ in range(thread_count):
                thread = threading.Thread(target=worker)
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            end_time = time.time()
            completion_times.append(end_time - start_time)

        # Should scale reasonably with thread count
        # More threads should not make it exponentially slower
        base_time = completion_times[0]
        for i, time_taken in enumerate(completion_times[1:], 1):
            thread_count = thread_counts[i]
            # Time shouldn't increase more than linearly with thread count
            expected_max_time = base_time * thread_count * 0.5  # Allow 50% overhead per thread
            assert time_taken < expected_max_time, \
                   f"Performance with {thread_count} threads too slow: {time_taken}s"


@pytest.mark.slow
class TestBenchmarkIntegration:
    """Integration with benchmark utilities."""

    def test_domain_lookup_benchmark(self):
        """Test domain lookup benchmark utility."""
        resolver = calmweb.BlocklistResolver([])
        resolver.blocked_domains = {"malware.com", "phishing.net"}
        resolver.whitelisted_domains_local = {"safe.com", "trusted.org"}

        test_domains = ["malware.com", "safe.com", "unknown.com", "192.168.1.1"]

        benchmark = PerformanceBenchmark()
        results = benchmark.benchmark_domain_lookup(resolver, test_domains, iterations=100)

        # Should have all expected metrics
        assert 'blocked_check_time' in results
        assert 'whitelist_check_time' in results
        assert 'ip_check_time' in results
        assert 'total_operations' in results
        assert 'avg_blocked_check' in results

        # Should be reasonably fast
        assert results['avg_blocked_check'] < 0.001  # Less than 1ms per check
        assert results['avg_whitelist_check'] < 0.001
        assert results['avg_ip_check'] < 0.001

    def test_logging_benchmark(self):
        """Test logging benchmark utility."""
        benchmark = PerformanceBenchmark()
        results = benchmark.benchmark_logging_performance(message_count=1000)

        # Should have all expected metrics
        assert 'total_time' in results
        assert 'messages_logged' in results
        assert 'avg_time_per_message' in results
        assert 'messages_per_second' in results

        # Should be reasonably fast
        assert results['messages_per_second'] > 1000  # At least 1000 messages/sec
        assert results['avg_time_per_message'] < 0.001  # Less than 1ms per message

    def test_config_parsing_benchmark(self, temp_dir):
        """Test config parsing benchmark utility."""
        generator = TestDataGenerator()
        config_content = generator.generate_config_content(
            [f"blocked{i}.com" for i in range(1000)],
            [f"safe{i}.com" for i in range(500)]
        )

        benchmark = PerformanceBenchmark()
        results = benchmark.benchmark_config_parsing(config_content, iterations=50)

        # Should have all expected metrics
        assert 'total_time' in results
        assert 'iterations' in results
        assert 'avg_time_per_parse' in results
        assert 'parses_per_second' in results
        assert 'config_size_bytes' in results

        # Should be reasonably fast
        assert results['parses_per_second'] > 10  # At least 10 parses/sec
        assert results['avg_time_per_parse'] < 0.1  # Less than 100ms per parse