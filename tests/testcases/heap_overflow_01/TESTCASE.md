# Test Case: heap_overflow_01

## Metadata
- **Engine**: source
- **Input Engine**: ida
- **Entry Functions**: parse_packet
- **Timeout**: 900 seconds
- **Tags**: buffer_overflow, memcpy, simple, heap

## Description

This testcase demonstrates a classic heap buffer overflow caused by an unchecked `memcpy`. The vulnerability is simple and should be directly detectable from the entry function.

## Expected Vulnerabilities

### Vulnerability 1: Heap Buffer Overflow in parse_packet

The `parse_packet` function copies attacker-controlled data into a fixed-size heap buffer without validating the requested copy length.

- **Location**: The `memcpy` call in `parse_packet`
- **Root Cause**: `len` is used as the copy size but never checked against the 64-byte buffer in `Packet`
- **Data Flow**: `data` and `len` come from the caller, then flow directly into `memcpy(pkt->buffer, data, len)`
- **Severity**: HIGH or MEDIUM
- **Attack Scenario**: An attacker can send more than 64 bytes and corrupt adjacent heap memory

The evaluator should treat this as a true positive if the system identifies an unchecked heap write on the `memcpy` call.
