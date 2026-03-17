# Test Case: cross_func_overflow_01

## Metadata
- **Engine**: source
- **Input Engine**: ida
- **Entry Functions**: handle_request
- **Timeout**: 900 seconds
- **Tags**: buffer_overflow, cross_function, data_flow, strcpy

## Description

This testcase requires cross-function data-flow analysis. Attacker-controlled input reaches `copy_data`, where an unsafe `strcpy` writes into a fixed-size stack buffer.

## Expected Vulnerabilities

### Vulnerability 1: Buffer Overflow via Cross-Function Data Flow

The vulnerability is in the helper function `copy_data`, but it should still be attributed to entry-point driven attacker input from `handle_request`.

- **Location**: `strcpy(dest, src)` in `copy_data`
- **Root Cause**: `strcpy` copies attacker-controlled data into a 64-byte stack buffer without a bounds check
- **Data Flow**: `handle_request(input)` passes `input` directly to `copy_data(src)`, which then copies `src` into `dest`
- **Severity**: HIGH
- **Attack Scenario**: A long request string can overwrite stack data and potentially the return address

The evaluator should prefer reports that include the cross-function propagation, not just a local `strcpy` warning with no taint explanation.
