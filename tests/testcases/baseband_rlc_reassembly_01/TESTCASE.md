# Test Case: baseband_rlc_reassembly_01

## Metadata
- **Engine**: source
- **Skill**: eval_source_scan
- **Entry Functions**: rlc_process_data_blocks
- **Timeout**: 300 seconds
- **Tags**: heap_overflow, fragment_reassembly, baseband, struct_corruption, cross_function, multi_stage

## Description

Inspired by CVE-2023-41112 (Samsung Baseband RLC). This test case models a radio link control fragment reassembly engine. The `FragmentDescriptor` has fixed-size arrays (8 elements) followed by metadata fields (`n_blocks`, `total_size`, `allocated_size`). Individual fragment sizes are validated (<=64 bytes), but the fragment count is never checked against the array limit. When more than 8 fragments arrive, the array writes overflow into the metadata fields, corrupting `total_size` to a small value. The subsequent `concatenate_fragments` allocates a buffer based on the corrupted `total_size` but copies data based on actual fragment sizes, causing a heap buffer overflow.

Key complexity:
- Two-stage bug: array overflow corrupts metadata → metadata corruption causes allocation/copy mismatch
- Individual fragment validation passes (size <= 64), masking the count-based overflow
- `validate_fragments` checks `total_size` against MAX_PDU_SIZE, but the corrupted value passes
- 4-function call chain: `rlc_process_data_blocks` → `add_fragment` → `validate_fragments` → `concatenate_fragments`
- The root cause (missing count check) and the exploitable symptom (heap overflow in memcpy) are in different functions

## Source Code

See `source/vuln.c`

## Expected Vulnerabilities

### Vulnerability 1: Array Overflow in add_fragment Corrupting Descriptor Metadata

The `add_fragment` function writes to `block_offsets[idx]`, `block_sizes[idx]`, and `fragments[idx]` without checking `idx` against `MAX_FRAGMENTS`.

- **Location**: `desc->block_offsets[idx] = offset` / `desc->block_sizes[idx] = size` / `desc->fragments[idx] = frag_copy` in `add_fragment`
- **Root Cause**: `n_blocks` is incremented without bounds checking, and the index is used to write past the fixed 8-element arrays, corrupting adjacent struct fields
- **Data Flow**: `rlc_process_data_blocks` parses attacker-controlled data → calls `add_fragment` for each fragment → `idx` exceeds 8 → writes corrupt `n_blocks`, `total_size`, `allocated_size` fields
- **Severity**: HIGH
- **Attack Scenario**: An attacker sends more than 8 RLC data blocks. The array overflow corrupts the descriptor's metadata fields.

### Vulnerability 2: Heap Buffer Overflow in concatenate_fragments Due to Corrupted total_size

After the array overflow corrupts `total_size`, `concatenate_fragments` allocates a small buffer but copies all fragment data into it.

- **Location**: `memcpy(pdu->pdu_buffer + write_offset, desc->fragments[i], desc->block_sizes[i])` in `concatenate_fragments`
- **Root Cause**: `malloc(desc->total_size)` uses the corrupted (small) value, but the copy loop iterates over all `n_blocks` fragments with their actual sizes, writing far more data than allocated
- **Data Flow**: Corrupted `desc->total_size` → `malloc` allocates small buffer → loop copies actual fragment data → heap overflow
- **Severity**: CRITICAL
- **Attack Scenario**: The allocation/copy size mismatch enables controlled heap corruption, potentially allowing arbitrary code execution in the baseband processor.

The evaluator should reward reports that connect the array overflow (root cause) with the heap overflow (exploitable consequence) as a two-stage vulnerability chain.
