# Test Case: uaf_cross_func_01

## Metadata
- **Engine**: source
- **Skill**: eval_source_scan
- **Entry Functions**: process_data
- **Timeout**: 300 seconds
- **Tags**: uaf, use_after_free, cross_function, memory_safety

## Description

This testcase demonstrates a cross-function use-after-free. Memory is released in one helper and then dereferenced from another helper through a dangling global pointer.

## Source Code

See `source/vuln.c`

## Expected Vulnerabilities

### Vulnerability 1: Use-After-Free in use_buffer

The global pointer remains non-NULL after `free_buffer` releases it, then `use_buffer` dereferences the dangling pointer.

- **Location**: `memset(global_buf->data, 0, global_buf->size)` in `use_buffer`
- **Root Cause**: `free_buffer` frees `global_buf` and `global_buf->data` but never nulls the global pointer
- **Data Flow**: `process_data` allocates `global_buf`, `free_buffer` releases it, then `use_buffer` dereferences the stale pointer
- **Severity**: CRITICAL or HIGH
- **Attack Scenario**: Freed memory may be reallocated for attacker-controlled content before the dangling pointer is used

The evaluator should treat reports about dangling-pointer dereference after free as matches even if the wording differs from "use-after-free".
