#!/usr/bin/env python3
"""
CalmWeb Test Runner

Main script to run the CalmWeb test suite with various options.
Provides comprehensive testing capabilities including unit tests,
integration tests, security tests, and performance benchmarks.

Usage:
    python run_tests.py [options]

Examples:
    python run_tests.py                    # Run all tests
    python run_tests.py --unit             # Run only unit tests
    python run_tests.py --security         # Run only security tests
    python run_tests.py --coverage         # Run with coverage report
    python run_tests.py --benchmark        # Run performance benchmarks
    python run_tests.py --windows          # Run Windows-specific tests
"""

import argparse
import os
import sys
import subprocess
from pathlib import Path


def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(
        description="CalmWeb Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    # Test selection options
    parser.add_argument(
        '--unit', '-u',
        action='store_true',
        help='Run only unit tests'
    )

    parser.add_argument(
        '--integration', '-i',
        action='store_true',
        help='Run only integration tests'
    )

    parser.add_argument(
        '--security', '-s',
        action='store_true',
        help='Run only security tests'
    )

    parser.add_argument(
        '--performance', '-p',
        action='store_true',
        help='Run only performance tests'
    )

    parser.add_argument(
        '--windows', '-w',
        action='store_true',
        help='Run only Windows-specific tests'
    )

    parser.add_argument(
        '--network', '-n',
        action='store_true',
        help='Run tests that require network access'
    )

    parser.add_argument(
        '--slow',
        action='store_true',
        help='Include slow-running tests'
    )

    # Coverage options
    parser.add_argument(
        '--coverage', '-c',
        action='store_true',
        help='Run tests with coverage report'
    )

    parser.add_argument(
        '--coverage-html',
        action='store_true',
        help='Generate HTML coverage report'
    )

    parser.add_argument(
        '--coverage-xml',
        action='store_true',
        help='Generate XML coverage report'
    )

    # Output options
    parser.add_argument(
        '--verbose', '-v',
        action='count',
        default=0,
        help='Increase verbosity (can be used multiple times)'
    )

    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Reduce output verbosity'
    )

    parser.add_argument(
        '--junit-xml',
        metavar='FILE',
        help='Generate JUnit XML report'
    )

    parser.add_argument(
        '--html-report',
        metavar='FILE',
        help='Generate HTML test report'
    )

    # Execution options
    parser.add_argument(
        '--parallel', '-j',
        type=int,
        metavar='N',
        help='Run tests in parallel using N processes'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=300,
        metavar='SECONDS',
        help='Timeout for individual tests (default: 300s)'
    )

    parser.add_argument(
        '--benchmark',
        action='store_true',
        help='Run performance benchmarks'
    )

    parser.add_argument(
        '--fail-fast', '-x',
        action='store_true',
        help='Stop on first failure'
    )

    # Test selection
    parser.add_argument(
        'tests',
        nargs='*',
        help='Specific test files or test names to run'
    )

    args = parser.parse_args()

    # Build pytest command
    cmd = ['python', '-m', 'pytest']

    # Add verbosity
    if args.quiet:
        cmd.append('-q')
    elif args.verbose:
        cmd.extend(['-v'] * args.verbose)

    # Add parallel execution
    if args.parallel:
        cmd.extend(['-n', str(args.parallel)])

    # Add timeout
    cmd.extend(['--timeout', str(args.timeout)])

    # Add coverage options
    if args.coverage or args.coverage_html or args.coverage_xml:
        cmd.extend(['--cov=program', '--cov-report=term-missing'])

        if args.coverage_html:
            cmd.append('--cov-report=html')

        if args.coverage_xml:
            cmd.append('--cov-report=xml')

    # Add report options
    if args.junit_xml:
        cmd.extend(['--junit-xml', args.junit_xml])

    if args.html_report:
        cmd.extend(['--html', args.html_report, '--self-contained-html'])

    # Add fail-fast
    if args.fail_fast:
        cmd.append('-x')

    # Add benchmark options
    if args.benchmark:
        cmd.append('--benchmark-only')

    # Build marker expressions for test selection
    markers = []

    if args.unit:
        markers.append('unit')
    if args.integration:
        markers.append('integration')
    if args.security:
        markers.append('security')
    if args.performance:
        markers.append('slow')
    if args.windows:
        markers.append('windows')
    if args.network:
        markers.append('network')

    # Add slow tests only if explicitly requested
    if not args.slow and not args.performance:
        if markers:
            markers.append('not slow')
        else:
            cmd.extend(['-m', 'not slow'])

    # Build marker expression
    if markers:
        if len(markers) == 1:
            marker_expr = markers[0]
        else:
            # If multiple specific markers, use OR logic
            if any(m in ['unit', 'integration', 'security', 'windows'] for m in markers):
                specific_markers = [m for m in markers if m not in ['not slow']]
                if specific_markers:
                    marker_expr = ' or '.join(specific_markers)
                    if 'not slow' in markers:
                        marker_expr = f"({marker_expr}) and not slow"
                else:
                    marker_expr = ' and '.join(markers)
            else:
                marker_expr = ' and '.join(markers)

        cmd.extend(['-m', marker_expr])

    # Add specific tests if provided
    if args.tests:
        cmd.extend(args.tests)
    else:
        cmd.append('tests/')

    # Print command for debugging
    print("Running command:", ' '.join(cmd))
    print("=" * 80)

    # Check if pytest is installed
    try:
        subprocess.run(['python', '-m', 'pytest', '--version'],
                      check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("Error: pytest is not installed.")
        print("Please install test dependencies:")
        print("  pip install -r requirements-test.txt")
        return 1

    # Check if test directory exists
    if not Path('tests').exists():
        print("Error: tests directory not found.")
        print("Please run this script from the project root directory.")
        return 1

    # Run the tests
    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except KeyboardInterrupt:
        print("\nTest run interrupted by user.")
        return 130
    except Exception as e:
        print(f"Error running tests: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())