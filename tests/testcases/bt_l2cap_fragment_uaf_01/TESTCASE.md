# Test Case: bt_l2cap_fragment_uaf_01

## Metadata
- **Engine**: source
- **Skill**: eval_source_scan
- **Entry Functions**: l2cap_recv_fragment
- **Timeout**: 300 seconds
- **Tags**: use_after_free, bluetooth, l2cap, fragment_reassembly, cross_function, error_handling

## Description

Inspired by CVE-2025-21969 (Linux Bluetooth L2CAP UAF). This test case models a Bluetooth L2CAP fragment reassembly engine. Fragments are queued in a `ReassemblyEntry` array. When a continuation fragment is too large (protocol error), `handle_reassembly_error` frees the entry and its data buffer but does NOT remove the pointer from the queue or set it to NULL. Subsequent calls to `process_completed_entries` iterate the queue and dereference the dangling pointer, causing a use-after-free.

Key complexity:
- The UAF requires a specific sequence: start fragment → oversized continuation → any subsequent operation
- `handle_reassembly_error` is the root cause (missing queue cleanup), but the UAF manifests in `process_completed_entries`
- `append_fragment` correctly validates fragment size and returns error, but the error handler is buggy
- The freed memory may be reallocated between the free and the subsequent access
- 5-function interaction: `l2cap_recv_fragment` → `find_or_create_entry` → `append_fragment` → `handle_reassembly_error` → `process_completed_entries`

## Source Code

See `source/vuln.c`

## Expected Vulnerabilities

### Vulnerability 1: Use-After-Free in process_completed_entries via Dangling Queue Pointer

`handle_reassembly_error` frees a `ReassemblyEntry` but leaves the pointer in the queue. `process_completed_entries` later dereferences it.

- **Location**: `if (entry && entry->complete)` and `entry->data[0]` in `process_completed_entries`
- **Root Cause**: `handle_reassembly_error` calls `free(entry->data)` and `free(entry)` but does not set `chan->queue[i] = NULL` or remove the entry from the queue. The dangling pointer passes the `entry != NULL` check.
- **Data Flow**: `l2cap_recv_fragment` receives oversized continuation → `append_fragment` returns -1 → `handle_reassembly_error(chan, entry)` frees entry → queue still holds pointer → next `process_completed_entries` call reads freed memory via `entry->complete` and `entry->data[0]`
- **Severity**: CRITICAL
- **Attack Scenario**: A Bluetooth attacker sends a start fragment followed by an oversized continuation fragment. The error path frees the reassembly entry but leaves a dangling pointer. When the next fragment triggers queue processing, the freed memory is accessed. If the freed memory has been reallocated for attacker-controlled data, this enables arbitrary read/write.

The evaluator should reward reports that trace the error handling path and identify the missing queue cleanup as the root cause, distinguishing it from the manifestation site in process_completed_entries.
