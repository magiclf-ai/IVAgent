# Test Case: format_string_01

## Metadata
- **Engine**: source
- **Skill**: eval_source_scan
- **Entry Functions**: log_message
- **Timeout**: 300 seconds
- **Tags**: format_string, printf, simple

## Description

This testcase demonstrates a format string vulnerability where attacker-controlled input is passed directly to `printf` as the format string.

## Source Code

See `source/vuln.c`

## Expected Vulnerabilities

### Vulnerability 1: Format String Vulnerability in log_message

The `log_message` function uses external input directly as the format string argument to `printf`.

- **Location**: `printf(msg)` in `log_message`
- **Root Cause**: The code does not use a safe literal format such as `printf("%s", msg)`
- **Data Flow**: The `msg` parameter flows directly into the format-string position of `printf`
- **Severity**: HIGH or CRITICAL
- **Attack Scenario**: An attacker can inject `%x`, `%s`, or `%n` and read or write memory

The evaluator should consider semantically equivalent reports about unsafe user-controlled format strings as matches.
