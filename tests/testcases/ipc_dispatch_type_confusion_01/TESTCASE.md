# Test Case: ipc_dispatch_type_confusion_01

## Metadata
- **Engine**: source
- **Input Engine**: ida
- **Entry Functions**: ipc_dispatch_message
- **Timeout**: 900 seconds
- **Tags**: type_confusion, ipc, partial_validation, cross_function, multi_handler, buffer_overflow

## Description

This test case models an IPC server with a message dispatcher and multiple handlers. The dispatcher validates the message header (type, total length) and routes to type-specific handlers. The auth handler (`handle_auth`) is fully validated — it checks exact payload size. The data handler (`handle_data`) dispatches further based on a `data_subtype` field. The TEXT subtype path has partial validation (`sanitize_text` checks for null terminator but doesn't validate `text_len`). The STRUCT subtype path has no validation of `field_count` against the fixed array size.

Key complexity:
- Multi-level dispatch: `ipc_dispatch_message` → `handle_data` → subtype switch
- One handler (auth) is safe, another (data) has two vulnerable sub-paths
- TEXT path: `sanitize_text` provides false sense of security (checks terminator, not length)
- STRUCT path: `field_count` is attacker-controlled, used as loop bound for array access
- The dispatcher's length validation is correct but insufficient — it doesn't know about inner struct layouts

## Expected Vulnerabilities

### Vulnerability 1: Buffer Overflow in TEXT Subtype via Unchecked text_len

`sanitize_text` validates null terminator presence but `text_len` is used directly in `memcpy` without checking it against the buffer size.

- **Location**: `memcpy(local_buf, td->text, td->text_len)` in `handle_data` TEXT case
- **Root Cause**: `td->text_len` is attacker-controlled. `sanitize_text` only checks for null terminator within 64 bytes but doesn't constrain `text_len`. If `text_len > 64`, the memcpy overflows `local_buf`.
- **Data Flow**: `ipc_dispatch_message` → `handle_data` → TEXT case → `sanitize_text` passes (null found) → `memcpy` uses unchecked `td->text_len` → stack overflow
- **Severity**: HIGH
- **Attack Scenario**: Attacker sends IPC DATA message with TEXT subtype, text_len=200, and a null byte within the first 64 bytes. sanitize_text passes, but memcpy copies 200 bytes into a 64-byte stack buffer.

### Vulnerability 2: Out-of-Bounds Array Access in STRUCT Subtype via Unchecked field_count

`field_count` controls the loop that accesses `field_offsets[]` (16 elements) without bounds checking.

- **Location**: `sd->field_offsets[i]` and `sd->field_data[off] = 0xFF` in `handle_data` STRUCT case
- **Root Cause**: `field_count` is attacker-controlled and never checked against 16. The loop reads past `field_offsets[16]`, and the read values are used as indices into `field_data[256]`.
- **Data Flow**: `ipc_dispatch_message` → `handle_data` → STRUCT case → loop with `i < sd->field_count` → reads `field_offsets[i]` past array bounds → uses result as index into `field_data`
- **Severity**: HIGH
- **Attack Scenario**: Attacker sends IPC DATA message with STRUCT subtype and field_count=20. The loop reads 4 entries past the field_offsets array, potentially using corrupted offset values to write 0xFF at arbitrary positions within field_data or beyond.

The evaluator should reward reports that identify the contrast between the safe auth handler and the vulnerable data handler paths, and note that sanitize_text provides incomplete protection.
