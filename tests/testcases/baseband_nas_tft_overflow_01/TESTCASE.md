# Test Case: baseband_nas_tft_overflow_01

## Metadata
- **Engine**: source
- **Input Engine**: ida
- **Entry Functions**: parse_tft_ie
- **Timeout**: 900 seconds
- **Tags**: heap_overflow, multi_level_parsing, tlv, baseband, partial_validation, cross_function

## Description

Inspired by CVE-2023-21517 (Samsung Baseband LTE ESM TFT). This test case models a multi-level TLV parser for a baseband NAS Traffic Flow Template IE. The outer IE length is validated, and the inner packet filter's total component byte count is validated against the declared length. However, the component *count* is never checked against the fixed-size pointer array (10 elements). A crafted packet filter with many small (2-byte) components passes all length checks but overflows the `components[]` array, corrupting adjacent heap memory.

Key complexity:
- 3-level parsing chain: `parse_tft_ie` → `parse_packet_filter` → `parse_component`
- Two-pass parsing in `parse_packet_filter`: first pass validates byte budget, second pass stores pointers
- The byte-budget validation in pass 1 succeeds, masking the array overflow in pass 2
- Attacker controls component count indirectly through packet filter length field

## Expected Vulnerabilities

### Vulnerability 1: Heap Buffer Overflow via Component Array Overflow in parse_packet_filter

The `components[]` array in `PacketFilterDesc` holds 10 pointers, but the parser stores up to ~125 component pointers without bounds checking the index.

- **Location**: `pf->components[idx] = comp` in `parse_packet_filter`
- **Root Cause**: The two-pass parser validates total component bytes against `pf_length` but never checks `comp_count`/`idx` against `MAX_COMPONENTS` (10). The array size and byte budget are independent constraints, and only the byte budget is enforced.
- **Data Flow**: `parse_tft_ie(ie_data, ie_len)` → `parse_packet_filter(data, remaining)` extracts `pf_length` from attacker data → second pass loop calls `parse_component` and stores returned pointers at incrementing `idx` → `idx` exceeds 10, writing past `components[]`
- **Severity**: CRITICAL
- **Attack Scenario**: An attacker sends a crafted NAS message with a TFT IE containing a packet filter with 20+ minimal components. The byte-level validation passes, but the pointer writes overflow the fixed array, corrupting adjacent `PacketFilterDesc` fields and potentially enabling code execution in the baseband processor.

The evaluator should reward reports that identify the disconnect between byte-budget validation and array-size validation as the root cause, and trace the taint through all three parsing levels.
