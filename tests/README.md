# reconductor Test Suite

## Overview

This directory contains unit and integration tests for reconductor.

## Structure

```
tests/
├── README.md                  # This file
├── __init__.py               # Test package init
├── test_utils.py             # Tests for IP validation, parsing, file operations
├── test_state.py             # Tests for state management and persistence
├── test_config.py            # Tests for configuration validation
├── test_scanner.py           # Tests for worker logic (TODO)
└── integration/
    └── test_scan_flow.py     # End-to-end integration tests (TODO)
```

## Running Tests

### Run All Tests

```bash
# From the reconductor directory
python3 -m pytest tests/

# Or using unittest
python3 -m unittest discover tests/
```

### Run Specific Test File

```bash
python3 -m pytest tests/test_utils.py
python3 -m pytest tests/test_state.py

# Or with unittest
python3 tests/test_utils.py
python3 tests/test_state.py
```

### Run Specific Test Case

```bash
python3 -m pytest tests/test_utils.py::TestIPValidation
python3 -m pytest tests/test_utils.py::TestIPValidation::test_valid_single_ips
```

### Run with Verbose Output

```bash
python3 -m pytest tests/ -v
python3 -m unittest discover tests/ -v
```

### Run with Coverage

```bash
# Install coverage first
pip3 install coverage pytest-cov

# Run with coverage
python3 -m pytest tests/ --cov=. --cov-report=html
coverage run -m pytest tests/
coverage report
coverage html
```

## Test Categories

### Unit Tests (`test_*.py`)

**test_utils.py** - Tests utility functions
- IP address validation (valid/invalid formats)
- IP validation edge cases (leading zeros, out-of-range octets)
- CIDR subnet validation
- Subnet splitting into /24 chunks
- Target name sanitization
- File operations (save lists)
- Parsing nmap output files

**test_state.py** - Tests state management
- ScanState creation and persistence
- Target addition and updates
- Stage transitions and tracking
- Queue management (prevent duplicates)
- State save/load (JSON persistence)
- Atomic writes (crash safety)
- Statistics and reporting
- Resume functionality

**test_config.py** - Tests configuration (TODO)
- Config validation
- Parameter range checking
- Invalid path detection
- Scan mode validation

**test_scanner.py** - Tests worker logic (TODO)
- Worker queue processing
- Command formatting
- Timeout handling
- Error recovery

### Integration Tests (`integration/`)

**test_scan_flow.py** - End-to-end tests (TODO)
- Full scan workflow
- Multi-stage progression
- Worker coordination
- State persistence across restarts

## Test Coverage

Current test coverage:

| Module | Coverage | Status |
|--------|----------|--------|
| `utils.py` | ~90% | ✅ Complete |
| `state.py` | ~95% | ✅ Complete |
| `config.py` | ~60% | ⚠️  Partial |
| `scanner.py` | ~20% | 🚧 TODO |
| `reconductor.py` | ~10% | 🚧 TODO |

## Writing New Tests

### Test Template

```python
#!/usr/bin/env python3
"""
Description of what this test file tests
"""

import os
import sys
import unittest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from module_to_test import function_or_class


class TestSomething(unittest.TestCase):
    """Test description"""

    def setUp(self):
        """Set up test fixtures"""
        pass

    def tearDown(self):
        """Clean up after test"""
        pass

    def test_feature(self):
        """Test a specific feature"""
        # Arrange
        input_data = "test"
        
        # Act
        result = function_to_test(input_data)
        
        # Assert
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
```

### Best Practices

1. **Test Isolation**: Each test should be independent
2. **Use setUp/tearDown**: Clean up temporary files and state
3. **Clear Names**: Test names should describe what they test
4. **One Assertion**: Focus on testing one thing per test
5. **Edge Cases**: Test boundary conditions and error cases
6. **Mock External Deps**: Don't call real nmap/nuclei in unit tests

## Critical Test Cases

### IP Validation Edge Cases ✅
- [x] Valid single IPs
- [x] Valid CIDR subnets
- [x] Out-of-range octets (256+)
- [x] Leading zeros (octal ambiguity)
- [x] Invalid formats (too many/few octets)
- [x] Invalid CIDR prefixes (/33, /0)
- [x] Edge cases (0.0.0.0, 255.255.255.255)

### Subnet Splitting Accuracy ✅
- [x] /24 remains unchanged
- [x] /23 splits into 2× /24
- [x] /16 splits into 256× /24
- [x] /8 splits into 65,536× /24
- [x] Single IPs remain unchanged
- [x] Invalid targets return empty list

### State Persistence ✅
- [x] Save to JSON file
- [x] Load from JSON file
- [x] Atomic writes (temp file)
- [x] Handle corrupted files
- [x] Handle empty files
- [x] Multiple rapid saves

### Queue Duplicate Prevention ✅
- [x] Mark target as queued
- [x] Don't return queued targets
- [x] Mark as dequeued when processing
- [x] Handle multiple workers

### Timeout Handling 🚧
- [ ] Command times out correctly
- [ ] Timeout value respected
- [ ] State updated on timeout
- [ ] Worker continues with next task

### Resume Functionality ✅
- [x] State persists across restarts
- [x] Incomplete targets identified
- [x] Stage progression continues
- [x] No duplicate work

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - name: Run tests
        run: |
          python3 -m unittest discover tests/
```

## Dependencies

Tests use only Python standard library:
- `unittest` - Test framework
- `tempfile` - Temporary files/directories
- `json` - JSON parsing
- `pathlib` - Path operations

Optional:
- `pytest` - Alternative test runner (better output)
- `coverage` - Code coverage reporting

## Troubleshooting

### Import Errors

If you get import errors:
```bash
# Make sure you're running from the reconductor directory
cd /path/to/reconductor
python3 tests/test_utils.py
```

### Permission Errors

Tests create temporary files - ensure write permissions:
```bash
# Check permissions
ls -la /tmp
```

### Mock nmap/nuclei

For integration tests, you'll need to mock external commands:
```python
from unittest.mock import patch

@patch('subprocess.run')
def test_scan(mock_run):
    mock_run.return_value.returncode = 0
    # Test your scan logic
```

## Future Test Additions

High Priority:
- [ ] `test_config.py` - Complete configuration validation tests
- [ ] `test_scanner.py` - Worker queue and command execution tests
- [ ] Integration tests for full scan workflow

Medium Priority:
- [ ] Performance tests (large target lists)
- [ ] Stress tests (many concurrent workers)
- [ ] Network timeout simulation

Low Priority:
- [ ] UI/CLI tests (argparse validation)
- [ ] Documentation tests (examples work)

---

**Test Status**: 🟢 Core functionality tested, 🟡 Integration tests needed

**Maintainer**: Add your name here
**Last Updated**: 2024-11-28