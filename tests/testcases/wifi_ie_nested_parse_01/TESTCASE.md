# Test Case: wifi_ie_nested_parse_01

## Metadata
- **Engine**: source
- **Input Engine**: ida
- **Entry Functions**: process_mgmt_frame
- **Timeout**: 900 seconds
- **Tags**: heap_overflow, nested_parsing, wifi, partial_validation, cross_function, array_overflow

## Description

Inspired by WiFi driver IE parsing vulnerabilities (CVE-2024-30078 class). This test case models a WiFi management frame parser with nested Information Elements. The outer frame parser validates that each IE fits within the frame boundary. Inside a vendor-specific IE, sub-elements are parsed: PMKID lists and cipher suites. The PMKID parser correctly validates count against both byte budget AND array size. However, the cipher suite parser only validates count against byte budget, not against `MAX_CIPHER_SUITES` (4). This inconsistent validation means one sub-element type is safe while another is vulnerable.

Key complexity:
- 4-level call chain: `process_mgmt_frame` → `parse_vendor_ie` → `parse_cipher_suites` / `parse_pmkid_list`
- Partial validation: PMKID path is fully validated (count <= MAX_PMKIDS), cipher path is not
- Outer IE length check passes, sub-element byte budget check passes, only array bounds check is missing
- The vulnerability requires understanding that `parse_pmkid_list` is safe but `parse_cipher_suites` is not

## Expected Vulnerabilities

### Vulnerability 1: Stack Buffer Overflow in parse_cipher_suites via Unchecked Count

The cipher suite count is validated against byte budget but not against `MAX_CIPHER_SUITES`, allowing writes past the fixed `cipher_suites[4][4]` array.

- **Location**: `memcpy(result->cipher_suites[i], data + 2 + i * 4, 4)` in `parse_cipher_suites`
- **Root Cause**: `count` is checked against `sub_len` (byte budget) but not against `MAX_CIPHER_SUITES` (4). A count of 8 with matching sub_len passes the byte check but overflows the array.
- **Data Flow**: `process_mgmt_frame(frame, frame_len)` → validates IE fits in frame → `parse_vendor_ie` iterates sub-elements → `parse_cipher_suites(data, sub_len, result)` → loop writes `count` entries into `cipher_suites[MAX_CIPHER_SUITES]` → overflow when count > 4
- **Severity**: HIGH
- **Attack Scenario**: An attacker sends a crafted WiFi management frame with a vendor IE containing a cipher suite sub-element with count > 4. The outer frame and IE length checks pass, the byte budget check passes, but the array overflow corrupts adjacent fields in `ParsedVendorIE` on the stack, potentially enabling code execution in the WiFi driver context.

The evaluator should note that `parse_pmkid_list` is correctly validated (count <= MAX_PMKIDS) while `parse_cipher_suites` is not — this inconsistency is the key finding.
