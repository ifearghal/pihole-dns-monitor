# Testing Documentation - PiHole Monitor

## Overview

This document describes the testing strategy and procedures for the PiHole Monitor project, with a strong focus on security-critical functions.

## Test Structure

```
test/
├── test_security.py       # Security-focused unit tests (NEW)
├── test_analyze.py        # Analysis function tests (existing)
├── test_anomaly.py        # Anomaly detection tests (existing)
├── generate_mock_logs.py  # Test data generation utility
└── data/                  # Test data files
```

## Running Tests

### Prerequisites

Install testing dependencies:

```bash
pip install -r requirements.txt
```

### Basic Test Execution

Run all tests:
```bash
pytest
```

Run with verbose output:
```bash
pytest -v
```

Run specific test file:
```bash
pytest test/test_security.py
```

Run specific test class:
```bash
pytest test/test_security.py::TestPathTraversalProtection
```

Run specific test:
```bash
pytest test/test_security.py::TestPathTraversalProtection::test_path_traversal_blocked_parent_directory
```

### Coverage Reports

Generate coverage report:
```bash
pytest --cov=src --cov-report=html
```

View HTML coverage report:
```bash
open htmlcov/index.html
```

Generate terminal coverage report:
```bash
pytest --cov=src --cov-report=term-missing
```

### Test Categories

Run only security tests:
```bash
pytest -m security
```

Run all except slow tests:
```bash
pytest -m "not slow"
```

## Security Test Suite

The `test_security.py` file contains comprehensive tests for security-critical functions:

### 1. Path Traversal Protection (`TestPathTraversalProtection`)

**Purpose:** Prevent unauthorized file system access via malicious paths.

**Tests:**
- ✅ `test_valid_path_within_allowed_directory` - Valid paths should pass
- ✅ `test_path_traversal_blocked_parent_directory` - Block `../` attacks
- ✅ `test_path_traversal_blocked_absolute_path` - Block absolute path escapes
- ✅ `test_path_traversal_blocked_symlink_escape` - Block symlink escapes
- ✅ `test_path_must_exist_for_read_mode` - File existence validation
- ✅ `test_bulletin_parent_directory_must_exist` - Directory validation

**Function tested:** `PiHoleMonitor._validate_path()`

**Attack vectors prevented:**
- Path traversal with `../`
- Absolute path injection
- Symlink escape attempts
- Access to files outside allowed directories

### 2. Output Sanitization (`TestOutputSanitization`)

**Purpose:** Prevent injection attacks via malicious log data in bulletin board output.

**Tests:**
- ✅ `test_sanitize_output_removes_control_chars` - Remove dangerous control characters
- ✅ `test_sanitize_output_preserves_newlines_and_tabs` - Preserve safe formatting
- ✅ `test_sanitize_output_truncates_long_text` - Prevent bulletin pollution
- ✅ `test_sanitize_output_handles_unicode` - Safe Unicode handling
- ✅ `test_sanitize_output_prevents_ansi_escape` - Remove ANSI escapes
- ✅ `test_sanitize_output_handles_null_byte` - Null byte injection prevention
- ✅ `test_sanitize_output_converts_non_string` - Type safety

**Function tested:** `PiHoleMonitor._sanitize_output()`

**Attack vectors prevented:**
- Control character injection
- ANSI escape sequence injection
- Null byte injection
- Bulletin board pollution
- Terminal escape attacks

### 3. IP Address Validation (`TestIPAddressValidation`)

**Purpose:** Ensure only valid IP addresses are processed from log files.

**Tests:**
- ✅ `test_parse_valid_ipv4_address` - Accept valid IPv4
- ✅ `test_parse_valid_ipv6_address` - Accept valid IPv6
- ✅ `test_parse_invalid_ip_rejected` - Reject malformed IPs
- ✅ `test_parse_ipv4_with_special_chars_rejected` - Block injection attempts

**Function tested:** `PiHoleMonitor.parse_log_line()`

**Attack vectors prevented:**
- SQL injection via IP field
- Command injection
- Log injection
- Invalid data processing

### 4. Domain Validation (`TestDomainValidation`)

**Purpose:** Validate domain names conform to RFC standards and size limits.

**Tests:**
- ✅ `test_parse_normal_domain` - Accept valid domains
- ✅ `test_parse_subdomain` - Accept subdomains
- ✅ `test_parse_rejects_oversized_domain` - Reject oversized domains
- ✅ `test_parse_accepts_max_length_domain` - Accept RFC-compliant max length

**Function tested:** `PiHoleMonitor.parse_log_line()`

**Attack vectors prevented:**
- Buffer overflow attacks
- Resource exhaustion
- DoS via oversized domains

### 5. Line Length Protection (`TestLineLengthProtection`)

**Purpose:** Prevent DoS attacks via extremely long log lines.

**Tests:**
- ✅ `test_parse_normal_line_length` - Accept normal lines
- ✅ `test_parse_rejects_oversized_line` - Reject excessive length
- ✅ `test_parse_accepts_max_line_length` - Handle maximum gracefully

**Function tested:** `PiHoleMonitor.parse_log_line()`

**Attack vectors prevented:**
- Memory exhaustion DoS
- Processing time DoS
- Resource exhaustion

### 6. Alert Deduplication (`TestAlertDeduplication`)

**Purpose:** Prevent alert spam and bulletin board pollution.

**Tests:**
- ✅ `test_first_alert_not_duplicate` - First alert allowed
- ✅ `test_immediate_duplicate_detected` - Duplicates blocked
- ✅ `test_different_ips_not_duplicate` - Different alerts allowed
- ✅ `test_empty_anomalies_not_duplicate` - Edge case handling

**Function tested:** `PiHoleMonitor._is_duplicate_alert()`

**Attack vectors prevented:**
- Bulletin board spam
- Disk exhaustion
- Alert fatigue attacks

### 7. Timestamp Parsing (`TestTimestampParsing`)

**Purpose:** Correctly handle timestamps across year boundaries.

**Tests:**
- ✅ `test_parse_current_year_timestamp` - Current year parsing
- ✅ `test_parse_handles_year_rollover` - Year rollover fix

**Function tested:** `PiHoleMonitor.parse_log_line()`

**Bug fixes validated:**
- Year rollover bug (Dec 31 → Jan 1)
- Future timestamp detection

### 8. Resource Limits (`TestResourceLimits`)

**Purpose:** Enforce resource limits to prevent disk/memory exhaustion.

**Tests:**
- ✅ `test_bulletin_board_rotation_on_size_limit` - Automatic rotation

**Function tested:** `PiHoleMonitor.post_alert()`

**Attack vectors prevented:**
- Disk exhaustion
- Unbounded file growth

### 9. Configuration Loading (`TestConfigurationLoading`)

**Purpose:** Validate custom configuration handling.

**Tests:**
- ✅ `test_monitor_respects_custom_thresholds` - Custom settings applied

**Function tested:** `PiHoleMonitor.__init__()`

## Test Data Generation

Use the mock log generator for integration testing:

```bash
python test/generate_mock_logs.py --output test/data/mock.log --lines 10000
```

## Continuous Integration

### GitHub Actions (Recommended)

Create `.github/workflows/test.yml`:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: pytest --cov=src --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

### Pre-commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Run security tests before commit

echo "Running security tests..."
pytest test/test_security.py -v

if [ $? -ne 0 ]; then
    echo "❌ Security tests failed. Commit aborted."
    exit 1
fi

echo "✅ Security tests passed."
```

Make it executable:
```bash
chmod +x .git/hooks/pre-commit
```

## Security Test Best Practices

### 1. Test Every Security-Critical Function

Every function that:
- Processes external input
- Validates paths/files
- Sanitizes output
- Enforces limits
- Handles authentication/authorization

...must have comprehensive tests.

### 2. Test Attack Vectors

Tests should explicitly validate that known attack patterns are blocked:
- Path traversal (`../`, absolute paths, symlinks)
- Injection attacks (SQL, command, log, ANSI)
- DoS attacks (resource exhaustion, infinite loops)
- Buffer overflows (oversized inputs)

### 3. Test Edge Cases

- Empty inputs
- Null/None values
- Maximum size inputs
- Minimum size inputs
- Boundary conditions
- Unicode/special characters

### 4. Test Error Handling

- Invalid inputs should fail gracefully
- Errors should not leak sensitive information
- Failed operations should not corrupt state

### 5. Maintain High Coverage

Target: **>90% code coverage** for security-critical modules.

Check coverage:
```bash
pytest --cov=src --cov-report=term-missing
```

## Test Maintenance

### When Adding New Features

1. Write tests first (TDD)
2. Run existing tests to ensure no regressions
3. Update documentation
4. Add new attack vector tests if applicable

### When Fixing Bugs

1. Write a test that reproduces the bug
2. Verify the test fails
3. Fix the bug
4. Verify the test passes
5. Add the test to the suite

### Regular Security Audits

Schedule regular reviews:
- Monthly: Review new attack vectors in security news
- Quarterly: Full security test suite review
- Yearly: External security audit

## Troubleshooting

### Import Errors

If you get import errors, ensure the project structure is correct:

```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
pytest
```

Or use the test file directly:
```bash
python test/test_security.py
```

### Module Not Found

The test file adds the src directory to the path automatically:
```python
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
```

### Test Failures

1. Check error message for specific failure
2. Run individual test: `pytest test/test_security.py::TestClassName::test_name -v`
3. Add `--pdb` flag to drop into debugger on failure
4. Check test isolation (tmp_path fixtures)

## Code Coverage Goals

| Component | Target Coverage | Current Coverage |
|-----------|----------------|------------------|
| Path validation | 100% | - |
| Output sanitization | 100% | - |
| Input parsing | >95% | - |
| Alert handling | >90% | - |
| Overall | >90% | - |

Run `pytest --cov=src --cov-report=html` to generate detailed coverage reports.

## Additional Resources

- [pytest documentation](https://docs.pytest.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security.html)
- [CVE Database](https://cve.mitre.org/) - For researching known vulnerabilities

## Contributing

When contributing tests:

1. Follow existing test naming conventions
2. Add docstrings explaining test purpose
3. Group related tests in classes
4. Use descriptive assertion messages
5. Keep tests isolated (use fixtures)
6. Document attack vectors being tested

## Questions?

Contact the PiHole DNS Monitor Contributors for questions about:
- Test failures
- Adding new test scenarios
- Security concerns
- Coverage goals
