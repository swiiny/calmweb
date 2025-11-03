#!/usr/bin/env python3
"""
Test Installation Validator

Validates that the CalmWeb test suite is properly installed and configured.
Checks dependencies, test discovery, and basic functionality.
"""

import sys
import subprocess
import importlib.util
from pathlib import Path


def check_python_version():
    """Check Python version compatibility."""
    print("Checking Python version...")
    version = sys.version_info
    if version.major != 3 or version.minor < 8:
        print(f"[FAIL] Python {version.major}.{version.minor} is not supported. Requires Python 3.8+")
        return False
    print(f"[PASS] Python {version.major}.{version.minor}.{version.micro} is compatible")
    return True


def check_dependencies():
    """Check if required test dependencies are installed."""
    print("\nChecking test dependencies...")

    required_packages = [
        'pytest',
        'pytest_cov',
        'pytest_mock',
        'xdist',  # pytest-xdist imports as 'xdist'
        'pytest_timeout',
        'urllib3',
        'dns',
        'PIL',
    ]

    missing_packages = []

    for package in required_packages:
        try:
            spec = importlib.util.find_spec(package)
            if spec is None:
                missing_packages.append(package)
            else:
                print(f"[PASS] {package}")
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print(f"\n[FAIL] Missing packages: {', '.join(missing_packages)}")
        print("Install with: pip install -r requirements-test.txt")
        return False

    print("[PASS] All required packages are installed")
    return True


def check_test_structure():
    """Check test directory structure."""
    print("\nChecking test structure...")

    required_files = [
        'tests/__init__.py',
        'tests/conftest.py',
        'tests/test_core_functions.py',
        'tests/test_blocklist_resolver.py',
        'tests/test_proxy_handler.py',
        'tests/test_security.py',
        'tests/test_integration.py',
        'tests/test_windows_specific.py',
        'tests/test_performance.py',
        'tests/test_utilities.py',
        'pytest.ini',
        'requirements-test.txt',
        'run_tests.py',
    ]

    missing_files = []

    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
        else:
            print(f"[PASS] {file_path}")

    if missing_files:
        print(f"\n[FAIL] Missing files: {', '.join(missing_files)}")
        return False

    print("[PASS] All test files are present")
    return True


def check_pytest_configuration():
    """Check pytest configuration."""
    print("\nChecking pytest configuration...")

    try:
        # Check if pytest can be imported and run
        result = subprocess.run(
            [sys.executable, '-m', 'pytest', '--version'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            print(f"[PASS] pytest version: {result.stdout.strip()}")
        else:
            print(f"[FAIL] pytest error: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        print("[FAIL] pytest command timed out")
        return False
    except Exception as e:
        print(f"[FAIL] Error running pytest: {e}")
        return False

    return True


def check_test_discovery():
    """Check if pytest can discover tests."""
    print("\nChecking test discovery...")

    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pytest', '--collect-only', '-q'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            # Find line with test count
            for line in lines:
                if 'tests collected' in line:
                    print(f"[PASS] {line}")
                    return True
            print("[PASS] Tests discovered successfully")
        else:
            print(f"[FAIL] Test discovery failed: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        print("[FAIL] Test discovery timed out")
        return False
    except Exception as e:
        print(f"[FAIL] Error during test discovery: {e}")
        return False

    return True


def run_sample_test():
    """Run a sample test to verify functionality."""
    print("\nRunning sample test...")

    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pytest',
             'tests/test_core_functions.py::TestSafeStr::test_safe_str_normal_string',
             '-v'],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode == 0:
            print("[PASS] Sample test passed")
            return True
        else:
            print(f"[FAIL] Sample test failed: {result.stderr}")
            print(f"stdout: {result.stdout}")
            return False

    except subprocess.TimeoutExpired:
        print("[FAIL] Sample test timed out")
        return False
    except Exception as e:
        print(f"[FAIL] Error running sample test: {e}")
        return False


def check_main_module():
    """Check if main module can be imported."""
    print("\nChecking main module...")

    try:
        # Add program directory to path
        program_dir = Path('program')
        if not program_dir.exists():
            print("[FAIL] Program directory not found")
            return False

        sys.path.insert(0, str(program_dir))

        # Try to import the main module
        import calmweb
        print("[PASS] Main module imports successfully")

        # Check key components
        required_components = [
            '_safe_str',
            'log',
            'parse_custom_cfg',
            'BlocklistResolver',
            'BlockProxyHandler',
        ]

        missing_components = []
        for component in required_components:
            if not hasattr(calmweb, component):
                missing_components.append(component)
            else:
                print(f"[PASS] {component}")

        if missing_components:
            print(f"[FAIL] Missing components: {', '.join(missing_components)}")
            return False

        return True

    except ImportError as e:
        print(f"[FAIL] Cannot import main module: {e}")
        return False
    except Exception as e:
        print(f"[FAIL] Error checking main module: {e}")
        return False


def main():
    """Main validation function."""
    print("CalmWeb Test Suite Validation")
    print("=" * 40)

    checks = [
        check_python_version,
        check_dependencies,
        check_test_structure,
        check_pytest_configuration,
        check_main_module,
        check_test_discovery,
        run_sample_test,
    ]

    passed = 0
    total = len(checks)

    for check in checks:
        if check():
            passed += 1
        print()  # Empty line for readability

    print("=" * 40)
    print(f"Validation Results: {passed}/{total} checks passed")

    if passed == total:
        print("[SUCCESS] All checks passed! Test suite is ready to use.")
        print("\nNext steps:")
        print("  1. Run basic tests: python run_tests.py --unit")
        print("  2. Run all tests: python run_tests.py")
        print("  3. Run with coverage: python run_tests.py --coverage")
        print("  4. See tests/README.md for more options")
        return 0
    else:
        print(f"[FAILED] {total - passed} checks failed. Please fix the issues above.")
        print("\nCommon solutions:")
        print("  - Install dependencies: pip install -r requirements-test.txt")
        print("  - Ensure you're in the project root directory")
        print("  - Check Python version compatibility")
        return 1


if __name__ == '__main__':
    sys.exit(main())