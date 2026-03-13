# Test Case: rpc_multi_handler_overflow_01

## Metadata
- **Engine**: source
- **Skill**: eval_source_scan
- **Entry Functions**: rpc_dispatch
- **Timeout**: 300 seconds
- **Tags**: heap_overflow, rpc, nested_tlv, multi_handler, partial_validation, cross_function

## Description

This test case models an RPC server with three handlers: PING (safe, trivial), QUERY (safe, validates name length), and CONFIG (vulnerable, nested TLV parsing). The dispatcher validates the outer message envelope. The CONFIG handler parses top-level TLVs, and when it encounters a NESTED tag, delegates to `parse_nested_config`. The nested parser iterates NAME/VALUE TLV pairs but has two bugs: (1) it doesn't check the entry count against `MAX_CONFIG_ENTRIES` (8), and (2) it doesn't validate `val_len` against `MAX_VALUE_LEN` (64) before `memcpy`. The `parse_tlv` function correctly validates that each TLV fits within the buffer, but this only ensures the TLV data is readable — it doesn't ensure the data fits in the destination struct.

Key complexity:
- 4-level call chain: `rpc_dispatch` → `handle_config` → `parse_nested_config` → `parse_tlv`
- PING and QUERY handlers are safe, CONFIG is vulnerable — requires analyzing all paths
- `parse_tlv` provides correct buffer-boundary validation, creating false confidence
- Two independent bugs in `parse_nested_config`: array overflow (count) and buffer overflow (value length)
- The QUERY handler correctly checks `length >= MAX_NAME_LEN`, but the CONFIG handler doesn't replicate this pattern

## Source Code

See `source/vuln.c`

## Expected Vulnerabilities

### Vulnerability 1: Stack Buffer Overflow via Oversized Value in parse_nested_config

`val_len` from the VALUE TLV is used directly in `memcpy` without checking against `MAX_VALUE_LEN` (64).

- **Location**: `memcpy(config->entries[entry_idx].value, val_val, val_len)` in `parse_nested_config`
- **Root Cause**: `parse_tlv` validates that `val_len` fits within the nested buffer, but `parse_nested_config` doesn't check `val_len <= MAX_VALUE_LEN` before copying into the 64-byte `value` field. A VALUE TLV with length 70 passes `parse_tlv` but overflows the destination.
- **Data Flow**: `rpc_dispatch` → `handle_config` → `parse_nested_config(value, length, &config)` → `parse_tlv` returns val_len=70 → `memcpy` copies 70 bytes into 64-byte `config->entries[i].value` → overflow
- **Severity**: HIGH
- **Attack Scenario**: Attacker sends an RPC CONFIG message with a NESTED TLV containing a VALUE TLV with length > 64. The outer envelope and TLV parsing pass, but the memcpy overflows the ConfigEntry's value buffer, corrupting adjacent entries or stack data.

### Vulnerability 2: Array Overflow via Unchecked Entry Count in parse_nested_config

`entry_idx` is incremented without checking against `MAX_CONFIG_ENTRIES` (8).

- **Location**: `config->entries[entry_idx].name` and `config->entries[entry_idx].value` in `parse_nested_config`
- **Root Cause**: The loop increments `entry_idx` for each NAME/VALUE pair but never checks `entry_idx < MAX_CONFIG_ENTRIES`. With 10+ pairs, writes go past the `entries[8]` array.
- **Data Flow**: `rpc_dispatch` → `handle_config` → `parse_nested_config` → loop processes 10 NAME/VALUE pairs → `entry_idx` reaches 8+ → writes past `entries[]` array → corrupts `num_entries` and stack
- **Severity**: HIGH
- **Attack Scenario**: Attacker sends a CONFIG message with a NESTED TLV containing more than 8 NAME/VALUE pairs. Each pair is individually valid, but the count exceeds the fixed array, corrupting memory beyond the ConfigUpdate structure.

The evaluator should note that `handle_query` correctly validates `length >= MAX_NAME_LEN` while `parse_nested_config` does not replicate this check — the inconsistency between handlers is a key finding.
