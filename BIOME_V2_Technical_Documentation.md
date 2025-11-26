# BIOME Stream Version 2 - Technical Documentation

**Author:** Marc Brandt (mb4n6)  
**Date:** November 2025 
**Version:** 3.5.1

## Overview

BIOME Stream Version 2 is a binary file format used on iOS devices for storing structured data. Unlike Version 1, V2 uses a footer-based indexing system with CRC32 checksums for data integrity.

## File Structure

```
┌─────────────────────────────────────────┐
│ Header (32 Bytes)                       │ Offset 0
├─────────────────────────────────────────┤
│ Frame 1                                 │ Offset 32 (BASE)
│  ├─ CRC32 (4 Bytes)                     │
│  ├─ Unknown (4 Bytes)                   │
│  └─ Protobuf Payload (Variable)         │
├─────────────────────────────────────────┤
│ Padding (0-15 Bytes, 0x00)              │
├─────────────────────────────────────────┤
│ Frame 2                                 │
│  ├─ CRC32 (4 Bytes)                     │
│  ├─ Unknown (4 Bytes)                   │
│  └─ Protobuf Payload (Variable)         │
├─────────────────────────────────────────┤
│ Padding (0-15 Bytes, 0x00)              │
├─────────────────────────────────────────┤
│ ...                                     │
├─────────────────────────────────────────┤
│ Frame N                                 │
├─────────────────────────────────────────┤
│ Padding                                 │
├─────────────────────────────────────────┤
│ Footer Entry N (16 Bytes)               │
├─────────────────────────────────────────┤
│ Footer Entry N-1 (16 Bytes)             │
├─────────────────────────────────────────┤
│ ...                                     │
├─────────────────────────────────────────┤
│ Footer Entry 1 (16 Bytes)               │ End of file
└─────────────────────────────────────────┘
```

## Header Format (32 Bytes)

```
Offset  Length  Type       Description
------  ------  ---------  ---------------------------------------------
0x00    4       Magic      "SEGB" (0x53 45 47 42)
0x04    4       uint32     Unknown (often 0x00000047)
0x08    8       double     Timestamp (Apple Epoch, CFAbsoluteTime)
0x10    4       uint32     Unknown (often 0x0000000A)
0x14    12      bytes      Reserved/Unknown (often 0xFF FF FF FF 00...)
```

## Footer Format (16 Bytes per Entry)

Footer entries are read **from back to front** and point to the end of each frame:

```
Offset  Length  Type       Description
------  ------  ---------  ---------------------------------------------
0x00    4       uint32     Relative offset to frame end (from BASE=32)
0x04    4       uint32     Unknown (usually 0x00000001)
0x08    8       double     Timestamp (Apple Epoch, CFAbsoluteTime)
```

## Frame Structure

Each frame consists of:

### 1. Frame Header (8 Bytes)
```
Offset  Length  Type       Description
------  ------  ---------  ---------------------------------------------
0x00    4       uint32     CRC32 checksum of payload
0x04    4       uint32     Unknown (usually 0x0000000B)
```

### 2. Protobuf Payload (Variable Length)
Protocol Buffer serialized data with various fields.

### 3. Padding Bytes (0-15 Bytes)
Null bytes (0x00) between frames for alignment.

## Frame Calculation Algorithm

### Step 1: Read Footer Pointers

Work backwards from the last position of the file in 16-byte steps:

```python
BASE = 32  # Header size
file_size = len(data)

entries = []
offset = file_size - 16

while offset >= BASE:
    chunk = data[offset:offset+16]
    
    # Skip empty entries
    if chunk == b'\x00' * 16:
        offset -= 16
        continue
    
    # Parse footer entry
    end_rel, unknown, timestamp = struct.unpack('<IId', chunk)
    
    # Validation
    if 0 < end_rel < (file_size - BASE):
        entries.append((offset, end_rel, unknown, timestamp))
    else:
        break  # End of footer entries reached
    
    offset -= 16

# Sort entries by relative offset (ascending)
entries.sort(key=lambda x: x[1])
```

### Step 2: Calculate Frame Boundaries

For each footer entry:

```python
for idx, (footer_pos, end_rel, unknown, timestamp) in enumerate(entries):
    
    # Calculate frame start
    if idx == 0:
        # First frame starts directly after header
        frame_start = BASE  # = 32
    else:
        # Subsequent frames: end of previous + padding
        prev_end_rel = entries[idx - 1][1]
        prev_frame_end = BASE + prev_end_rel
        
        # Detect padding bytes (0x00)
        padding = 0
        while data[prev_frame_end + padding] == 0:
            padding += 1
            if padding > 16:  # Safety check
                break
        
        frame_start = prev_frame_end + padding
    
    # Calculate frame end (WITHOUT padding)
    frame_end = BASE + end_rel
    
    # Read header (8 bytes)
    crc32, unknown_field = struct.unpack('<II', 
                                          data[frame_start:frame_start+8])
    
    # Extract payload
    payload_start = frame_start + 8
    payload = data[payload_start:frame_end]
    payload_length = len(payload)
```

### Step 3: CRC32 Validation

```python
import zlib

# Calculate CRC32 of payload
calculated_crc = zlib.crc32(payload) & 0xFFFFFFFF

# Compare with header CRC32
crc_ok = (calculated_crc == crc32)
```

## Practical Example

Example from file `743240128536818`:

### Footer Pointer (last 16 bytes)
```
Offset: 0x0FFFF0 (1048560)
Bytes:  0C 05 00 00 01 00 00 00 74 B6 44 E0 78 26 C6 41

Parsed:
  Relative Offset:  0x0000050C = 1292 decimal
  Unknown:          0x00000001
  Timestamp:        743240128.536818 (2024-07-21 07:35:28.536 UTC)
```

### Frame 1 Calculation

```
Footer Offset:     1292 (relative to BASE=32)
Frame Start:       32 (first frame)
Frame End:         32 + 1292 = 1324
Payload Start:     32 + 8 = 40
Payload End:       1324
Payload Length:    1284 bytes

Header Bytes (Offset 32-39):
  C7 CB C5 00 0B 00 00 00
  CRC32:    0xC7CBC500
  Unknown:  0x0000000B

Payload (Offset 40-1323):
  09 00 00 00 E0 78 26 C6 41 12 11 63 6F 6D 2E 61...
```

### Frame 2 Calculation

```
Footer Offset:     5798 (relative to BASE=32)
Frame Start:       1324 (end of Frame 1, no padding)
Frame End:         32 + 5798 = 5830
Padding after Frame: 2 bytes (0x00 0x00) → Actual end: 5832
Payload Start:     1324 + 8 = 1332
Payload End:       5830
Payload Length:    4498 bytes

Header Bytes (Offset 1324-1331):
  73 4A 36 44 0B 00 00 00
  CRC32:    0x44364A73
  Unknown:  0x0000000B
```

### Frame 3 Calculation

```
Footer Offset:     10433 (relative to BASE=32)
Frame Start:       5832 (end of Frame 2 + 2 padding bytes)
Frame End:         32 + 10433 = 10465
Padding after Frame: 3 bytes (0x00 0x00 0x00) → Actual end: 10468
Payload Start:     5832 + 8 = 5840
Payload End:       10465
Payload Length:    4625 bytes
```

## Important Notes

### Padding Bytes

- Padding occurs between frames, not within
- Length: 0-15 bytes (typically 0-3 bytes)
- Value: Always 0x00
- Purpose: Likely alignment for performance

### Footer Offset is RELATIVE

⚠️ **CRITICAL:** The offset in the footer is **relative to position 32** (BASE), not absolute!

### CRC32 Calculation

```python
import zlib

# CRC32 is calculated only over the payload (without header!)
crc32_value = zlib.crc32(payload) & 0xFFFFFFFF
```

### Timestamp Format

Apple CFAbsoluteTime (seconds since 01.01.2001 00:00:00 UTC):

```python
from datetime import datetime, timezone, timedelta

APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

def apple_time_to_datetime(timestamp):
    return APPLE_EPOCH + timedelta(seconds=timestamp)
```

## Protobuf Payload Analysis

The payloads contain Protocol Buffer data. Typical fields:

### Field IDs (commonly occurring)

```
field_1:  Timestamp (double)
field_2:  Bundle Identifier (string) e.g. "com.apple.mobilesafari"
field_3:  Stream Identifier (string)
field_4:  Protobuf-nested (additional data)
```

### Example Decoding

```
Bytes: 09 00 00 00 E0 78 26 C6 41 12 11 63 6F 6D 2E 61...

09          → Wire Type 1 (fixed64), Field ID 1
00 00 00 E0 78 26 C6 41 → Double: 743240128.536818

12          → Wire Type 2 (length-delimited), Field ID 2
11          → Length: 17 bytes
63 6F 6D... → String: "com.apple.mobilesafari"
```

## Error Handling

### Validations

1. **Check header magic:** Must be "SEGB" (0x53454742)
2. **Footer offset validation:** `0 < offset < (file_size - 32)`
3. **Check frame boundaries:** `frame_start + 8 < frame_end`
4. **Verify CRC32:** Ensure payload integrity
5. **Padding limit:** Maximum 16 bytes padding between frames

### Error Tolerance

For faulty frames:
- Skip frame, continue with next
- Log CRC errors, but don't abort
- Padding anomalies (>16 bytes) → Warning, but continue parsing

## Parser Implementation

See `biome_core.py` class `BIOMEAnalyzer._analyze_v2()` for reference implementation.

### Key Algorithm

```python
def parse_biome_v2(file_path):
    BASE = 32
    data = open(file_path, 'rb').read()
    
    # 1. Validate header
    if data[:4] != b'SEGB':
        raise ValueError("Invalid BIOME V2 file")
    
    # 2. Collect footer entries
    entries = []
    offset = len(data) - 16
    while offset >= BASE:
        end_rel, unk, ts = struct.unpack('<IId', data[offset:offset+16])
        if 0 < end_rel < len(data) - BASE:
            entries.append((offset, end_rel, unk, ts))
        offset -= 16
    
    # 3. Sort by offset
    entries.sort(key=lambda x: x[1])
    
    # 4. Extract frames
    frames = []
    for idx, (_, end_rel, _, ts) in enumerate(entries):
        # Calculate start
        if idx == 0:
            start = BASE
        else:
            prev_end = BASE + entries[idx-1][1]
            padding = 0
            while data[prev_end + padding] == 0:
                padding += 1
            start = prev_end + padding
        
        # Calculate end
        end = BASE + end_rel
        
        # Header + Payload
        crc32 = struct.unpack('<I', data[start:start+4])[0]
        payload = data[start+8:end]
        
        # Validate CRC
        calc_crc = zlib.crc32(payload) & 0xFFFFFFFF
        
        frames.append({
            'offset': start,
            'length': len(payload),
            'crc32': crc32,
            'crc_ok': crc32 == calc_crc,
            'timestamp': ts,
            'payload': payload
        })
    
    return frames
```

## Version 2 vs. Version 1

| Feature              | Version 1               | Version 2                    |
|----------------------|-------------------------|------------------------------|
| **Indexing**         | Frame header based      | Footer-based                 |
| **Integrity**        | No checksums            | CRC32 per frame              |
| **Frame Search**     | Sequential scan         | Direct access via footer     |
| **Padding**          | 8-byte alignment        | Variable (0-15 bytes)        |
| **Timestamps**       | In frame header         | In footer entry              |
| **Efficiency**       | Slow for large files    | Fast, indexed                |

## Tools

### BIOME Analyzer

```bash
# Analyze all frames
python3 biome_analyzer.py file.biome --frames all --verbose

# With HTML report
python3 biome_analyzer.py file.biome -o output/

# GUI mode
python3 biome_analyzer.py --gui
```

### Export Formats

- **JSON:** Structured data with protobuf fields
- **CSV:** Table with frame metadata
- **HTML:** Interactive report with visualizations

## Forensic Relevance

BIOME Streams contain important activity data.

**Important for forensics:**
- Timestamps are in UTC (Apple Epoch)
- CRC32 checksums can reveal manipulations
- Deleted data may be present in unused areas

## Summary

BIOME Stream Version 2 uses a **footer-based index system** with CRC32 integrity checking. Correct calculation of frame positions requires:

1. **Read footer from back to front**
2. **Offsets are RELATIVE to position 32**
3. **Detect padding bytes between frames**
4. **Calculate CRC32 over payload (without header)**

With this knowledge, forensic analysts can parse BIOME V2 files completely and correctly.

---

**License:** For forensic and educational purposes  
