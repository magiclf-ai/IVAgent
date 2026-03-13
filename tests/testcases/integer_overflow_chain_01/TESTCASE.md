# Test Case: integer_overflow_chain_01

## Metadata
- **Engine**: source
- **Skill**: eval_source_scan
- **Entry Functions**: allocate_and_copy
- **Timeout**: 300 seconds
- **Tags**: integer_overflow, buffer_overflow, chain, complex

## Description

This testcase models a vulnerability chain. An integer overflow in size calculation causes a later heap buffer overflow during `memcpy`.

## Source Code

See `source/vuln.c`

## Expected Vulnerabilities

### Vulnerability 1: Integer Overflow in calculate_size

The size calculation multiplies two attacker-controlled integers without overflow checks.

- **Location**: `return count * item_size` in `calculate_size`
- **Root Cause**: Signed integer multiplication can wrap around to a much smaller value
- **Data Flow**: `count` and `item_size` come from the caller and are used directly in the multiplication
- **Severity**: MEDIUM
- **Attack Scenario**: Large values can overflow to zero or another small size that is later used by `malloc`

### Vulnerability 2: Buffer Overflow Enabled by Integer Overflow

The allocation size is based on the overflowed result, but the later copy still uses the large effective size.

- **Location**: `memcpy(buffer, data, count * item_size)` in `allocate_and_copy`
- **Root Cause**: `malloc(total_size)` receives the wrapped size while `memcpy` uses the large multiplication result
- **Data Flow**: `count` and `item_size` overflow in `calculate_size`, then the overflowed value feeds allocation and the large value feeds the copy
- **Severity**: HIGH or CRITICAL
- **Attack Scenario**: A tiny allocation is followed by a large copy that corrupts heap memory

The evaluator should reward reports that connect the arithmetic bug with the downstream memory corruption as a vulnerability chain.
