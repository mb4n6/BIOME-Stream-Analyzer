#!/usr/bin/env python3
import struct
import hashlib
import math
import base64
import json
import zlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any

APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
SEGB_MAGIC = b'SEGB'

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log(p, 2)
    return float(ent)

def hex_preview(data: bytes, length: int = 256) -> str:
    return " ".join(f"{b:02X}" for b in data[:length]) if data else ""

def ascii_preview(data: bytes, length: int = 256) -> str:
    if not data:
        return ""
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:length])

def apple_time_to_dt(ts: float) -> Optional[datetime]:
    if ts is None or not isinstance(ts, (int, float)):
        return None
    if not (-1e12 < ts < 1e12):
        return None
    try:
        return APPLE_EPOCH + timedelta(seconds=float(ts))
    except:
        return None

@dataclass
class FrameInfo:
    version: int
    index: Optional[int] = None
    offset: Optional[int] = None
    payload_offset: Optional[int] = None
    payload_length: Optional[int] = None
    size: Optional[int] = None
    timestamp: Optional[float] = None
    dt_created: Optional[datetime] = None
    dt_modified: Optional[datetime] = None
    datetime_obj: Optional[datetime] = None
    crc: Optional[int] = None
    crc_ok: Optional[bool] = None
    payload: Optional[bytes] = None
    binary_objects: List[Dict[str, Any]] = field(default_factory=list)
    protobuf_data: Dict[str, Any] = field(default_factory=dict)
    file_hash: Optional[str] = None
    
    def get_timestamp_str(self) -> str:
        dt = self.dt_created or self.datetime_obj
        if dt:
            return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        return "N/A"
    
    def get_frame_size(self) -> int:
        return self.payload_length or self.size or 0

BINARY_SIGS = {
    b'\xFF\xD8\xFF': 'JPEG',
    b'\x89PNG\r\n\x1a\n': 'PNG',
    b'bplist': 'Binary PLIST',
    b'GIF87a': 'GIF87a',
    b'GIF89a': 'GIF89a',
    b'RIFF': 'RIFF (WAV/AVI)',
    b'\x50\x4B\x03\x04': 'ZIP',
    b'%PDF': 'PDF',
    b'\x00\x00\x01\x00': 'ICO',
    b'BM': 'Bitmap',
    b'<?xml': 'XML',
    b'\x1F\x8B\x08': 'GZIP',
}

class BinaryObjectDetector:
    def __init__(self, min_size=100):
        self.min_size = min_size
    
    def detect(self, data: bytes) -> List[Dict[str, Any]]:
        if not data or len(data) < self.min_size:
            return []
        
        objects = []
        ent = calculate_entropy(data)
        
        if ent > 7.0:
            obj_type = "High Entropy Data"
            for sig, name in BINARY_SIGS.items():
                if data.startswith(sig):
                    obj_type = name
                    break
            
            objects.append({
                'type': obj_type,
                'size': len(data),
                'entropy': round(ent, 2),
                'offset': 0,
                'hex_preview': hex_preview(data, 256),
                'ascii_preview': ascii_preview(data, 256)
            })
        
        for sig, name in BINARY_SIGS.items():
            pos = 0
            while pos < len(data):
                idx = data.find(sig, pos)
                if idx == -1:
                    break
                if idx > 0:
                    remaining = len(data) - idx
                    if remaining >= self.min_size:
                        chunk_ent = calculate_entropy(data[idx:idx+min(1024, remaining)])
                        objects.append({
                            'type': name,
                            'size': remaining,
                            'entropy': round(chunk_ent, 2),
                            'offset': idx,
                            'hex_preview': hex_preview(data[idx:idx+256], 256),
                            'ascii_preview': ascii_preview(data[idx:idx+256], 256)
                        })
                pos = idx + len(sig)
        
        return objects

class ProtobufAnalyzer:
    def __init__(self, full_output=True):
        self.full_output = full_output
    
    def parse(self, data: bytes) -> Dict[str, Any]:
        if not data:
            return {}
        
        result = {}
        pos = 0
        field_num = 0
        
        while pos < len(data):
            if pos + 1 > len(data):
                break
            
            try:
                key = data[pos]
                wire_type = key & 0x07
                field_id = key >> 3
                pos += 1
                
                if wire_type == 0:
                    value, pos = self._read_varint(data, pos)
                    result[f"field_{field_id}"] = value
                elif wire_type == 1:
                    if pos + 8 <= len(data):
                        value = struct.unpack('<d', data[pos:pos+8])[0]
                        result[f"field_{field_id}"] = value
                        pos += 8
                elif wire_type == 2:
                    length, pos = self._read_varint(data, pos)
                    if pos + length <= len(data):
                        chunk = data[pos:pos+length]
                        try:
                            text = chunk.decode('utf-8', errors='strict')
                            if self.full_output:
                                result[f"field_{field_id}"] = text
                            else:
                                result[f"field_{field_id}"] = text[:100] + ('...' if len(text) > 100 else '')
                        except:
                            result[f"field_{field_id}"] = base64.b64encode(chunk).decode('ascii')
                        pos += length
                elif wire_type == 5:
                    if pos + 4 <= len(data):
                        value = struct.unpack('<f', data[pos:pos+4])[0]
                        result[f"field_{field_id}"] = value
                        pos += 4
                else:
                    break
                
                field_num += 1
                if field_num > 1000:
                    break
                    
            except:
                break
        
        return result
    
    def _read_varint(self, data, pos):
        result = 0
        shift = 0
        while pos < len(data) and shift < 64:
            byte = data[pos]
            pos += 1
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
        return result, pos

class BIOMEAnalyzer:
    def __init__(self, file_path, max_frames=5, verbose=False, full_output=True, 
                 min_binary_size=100, force_version=None, output_dir=None):
        self.file_path = Path(file_path)
        self.max_frames = max_frames
        self.verbose = verbose
        self.full_output = full_output
        self.min_binary_size = min_binary_size
        self.force_version = force_version
        self.output_dir = Path(output_dir) if output_dir else self.file_path.parent
        
        self.version = None
        self.frames = []
        self.file_hash = None
        self.file_size = 0
        
        self.binary_detector = BinaryObjectDetector(min_binary_size)
        self.protobuf_analyzer = ProtobufAnalyzer(full_output)
    
    def analyze(self) -> bool:
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            self.file_size = len(data)
            self.file_hash = hashlib.sha256(data).hexdigest()
            
            if self.verbose:
                print(f"File size: {self.file_size} bytes")
                print(f"File hash: {self.file_hash[:32]}...")
            
            if self.force_version:
                self.version = self.force_version
                if self.verbose:
                    print(f"Forced version: {self.version}")
            else:
                self.version = self._detect_version(data)
                if self.verbose:
                    print(f"Detected version: {self.version}")
            
            if self.version == 1:
                return self._analyze_v1(data)
            elif self.version == 2:
                return self._analyze_v2(data)
            else:
                print("ERROR: Could not detect BIOME version")
                print(f"File signature: {data[:8].hex() if len(data) >= 8 else 'too short'}")
                if len(data) >= 56:
                    print(f"Position 52-56: {data[52:56].hex()}")
                return False
                
        except FileNotFoundError:
            print(f"ERROR: File not found: {self.file_path}")
            return False
        except PermissionError:
            print(f"ERROR: Permission denied: {self.file_path}")
            return False
        except Exception as e:
            print(f"ERROR: Analysis failed: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False
    
    def _detect_version(self, data: bytes) -> Optional[int]:
        if len(data) < 56:
            return None
        
        if data[52:56] == SEGB_MAGIC:
            return 1
        
        if len(data) >= 32 and data[0:4] == SEGB_MAGIC:
            return 2
        
        return None
    
    def _analyze_v1(self, data: bytes) -> bool:
        STREAM_HEADER_SIZE = 56
        FRAME_HEADER_SIZE = 32
        PADDING_ALIGNMENT = 8
        
        if len(data) < STREAM_HEADER_SIZE:
            if self.verbose:
                print(f"File too small for V1: {len(data)} bytes (need at least {STREAM_HEADER_SIZE})")
            return False
        
        signature = data[52:56]
        if signature != SEGB_MAGIC:
            if self.verbose:
                print(f"Invalid V1 signature at position 52: {signature.hex()}")
            return False
        
        if self.verbose:
            print("✓ Valid BIOME Stream Version 1 detected")
        
        offset = STREAM_HEADER_SIZE
        frame_idx = 0
        
        while offset < len(data) and frame_idx < self.max_frames:
            if offset + FRAME_HEADER_SIZE > len(data):
                if self.verbose:
                    print(f"Reached end of file at offset {offset}")
                break
            
            frame_header = data[offset:offset + FRAME_HEADER_SIZE]
            
            if all(b == 0 for b in frame_header):
                if self.verbose:
                    print(f"Frame {frame_idx}: Null header at offset {offset}")
                break
            
            try:
                payload_length = struct.unpack('<I', frame_header[0:4])[0]
                ts_created = struct.unpack('<d', frame_header[8:16])[0]
                ts_modified = struct.unpack('<d', frame_header[16:24])[0]
                
                if payload_length > 100 * 1024 * 1024 or payload_length < 0:
                    if self.verbose:
                        print(f"Frame {frame_idx}: Invalid payload length {payload_length}")
                    break
                
                payload_start = offset + FRAME_HEADER_SIZE
                payload_end = payload_start + payload_length
                
                if payload_end > len(data):
                    if self.verbose:
                        print(f"Frame {frame_idx}: Payload extends beyond file")
                    break
                
                payload = data[payload_start:payload_end]
                
                next_offset = payload_end
                padding = (PADDING_ALIGNMENT - (next_offset % PADDING_ALIGNMENT)) % PADDING_ALIGNMENT
                if padding > 0:
                    next_offset += padding
                
                frame = FrameInfo(
                    version=1,
                    index=frame_idx,
                    offset=offset,
                    payload_offset=payload_start,
                    payload_length=payload_length,
                    dt_created=apple_time_to_dt(ts_created),
                    dt_modified=apple_time_to_dt(ts_modified),
                    payload=payload if len(payload) < 1024*1024 else None,
                    file_hash=self.file_hash
                )
                
                frame.binary_objects = self.binary_detector.detect(payload)
                frame.protobuf_data = self.protobuf_analyzer.parse(payload)
                self.frames.append(frame)
                
                offset = next_offset
                frame_idx += 1
                
            except struct.error as e:
                if self.verbose:
                    print(f"Frame {frame_idx}: Struct unpack error: {e}")
                break
            except Exception as e:
                if self.verbose:
                    print(f"Frame {frame_idx}: Error parsing: {e}")
                break
        
        if self.verbose:
            print(f"✓ Parsed {len(self.frames)} frames")
        
        return len(self.frames) > 0
    
    def _analyze_v2(self, data: bytes) -> bool:
        BASE = 32
        n = len(data)
        
        if n < BASE or data[:4] != SEGB_MAGIC:
            if self.verbose:
                print("Not a valid V2 BIOME stream")
            return False
        
        try:
            # Parse footer entries (working backwards from end of file)
            entries = []
            i = n - 16
            
            while i >= BASE:
                chunk = data[i:i+16]
                if chunk == b"\x00" * 16:
                    if entries:
                        break
                    i -= 16
                    continue
                
                try:
                    end_rel, unk, ts = struct.unpack('<IId', chunk)
                    if not (0 < end_rel < (n - BASE)):
                        break
                    entries.append((i, end_rel, unk, ts))
                except:
                    break
                
                i -= 16
            
            if not entries:
                if self.verbose:
                    print("No valid footer entries found")
                return False
            
            # Sort entries by relative offset (ascending order)
            entries_sorted = sorted(entries, key=lambda x: x[1])
            
            frame_idx = 0
            
            for idx, (file_off, end_rel, unk, ts) in enumerate(entries_sorted):
                if frame_idx >= self.max_frames:
                    break
                
                # Calculate frame start
                if idx == 0:
                    # First frame starts at BASE (32)
                    frame_start = BASE
                else:
                    # Subsequent frames: end of previous frame + padding
                    prev_end_rel = entries_sorted[idx - 1][1]
                    prev_frame_end = BASE + prev_end_rel
                    
                    # Detect padding bytes (0x00) after previous frame
                    padding = 0
                    while prev_frame_end + padding < len(data) and data[prev_frame_end + padding] == 0:
                        padding += 1
                        if padding > 16:  # Sanity check
                            break
                    
                    frame_start = prev_frame_end + padding
                
                # Calculate frame end (without padding)
                frame_end = BASE + end_rel
                
                # Validate frame boundaries
                if frame_start + 8 > frame_end or frame_end > len(data):
                    if self.verbose:
                        print(f"Frame {frame_idx}: Invalid boundaries (start={frame_start}, end={frame_end})")
                    continue
                
                # Read 8-byte frame header (CRC32 + Unknown)
                try:
                    crc32_hdr, unknown1 = struct.unpack('<II', data[frame_start:frame_start+8])
                except:
                    if self.verbose:
                        print(f"Frame {frame_idx}: Failed to read header at {frame_start}")
                    continue
                
                # Extract payload
                payload_offset = frame_start + 8
                payload = data[payload_offset:frame_end]
                payload_len = len(payload)
                
                # Calculate and verify CRC32
                calc_crc = zlib.crc32(payload) & 0xFFFFFFFF
                crc_ok = (calc_crc == crc32_hdr)
                
                # Create frame info
                frame = FrameInfo(
                    version=2,
                    index=frame_idx,
                    offset=frame_start,
                    payload_offset=payload_offset,
                    payload_length=payload_len,
                    size=payload_len,
                    timestamp=ts if isinstance(ts, (int, float)) and -3.5e8 <= ts <= 1.58e9 else None,
                    datetime_obj=apple_time_to_dt(ts) if isinstance(ts, (int, float)) and -3.5e8 <= ts <= 1.58e9 else None,
                    crc=crc32_hdr,
                    crc_ok=crc_ok,
                    payload=payload if len(payload) < 1024*1024 else None,
                    file_hash=self.file_hash
                )
                
                # Analyze payload
                frame.binary_objects = self.binary_detector.detect(payload)
                frame.protobuf_data = self.protobuf_analyzer.parse(payload)
                self.frames.append(frame)
                
                if self.verbose:
                    padding_info = f" (padding: {padding} bytes)" if idx > 0 and padding > 0 else ""
                    print(f"Frame {frame_idx}: offset={frame_start}, end={frame_end}, payload={payload_len} bytes, CRC={'OK' if crc_ok else 'FAIL'}{padding_info}")
                
                frame_idx += 1
            
            if self.verbose:
                print(f"✓ Parsed {len(self.frames)} V2 frames")
            
            return len(self.frames) > 0
            
        except Exception as e:
            if self.verbose:
                print(f"Error analyzing v2: {e}")
                import traceback
                traceback.print_exc()
            return False
    
    def export_json(self, output_path=None):
        if output_path is None:
            output_path = self.output_dir / f"{self.file_path.stem}.json"
        
        data = {
            'file': str(self.file_path),
            'version': self.version,
            'file_size': self.file_size,
            'file_hash': self.file_hash,
            'frame_count': len(self.frames),
            'frames': []
        }
        
        for frame in self.frames:
            frame_data = {
                'index': frame.index,
                'offset': frame.offset,
                'size': frame.get_frame_size(),
                'timestamp': frame.get_timestamp_str(),
                'binary_objects': frame.binary_objects,
                'protobuf_fields': frame.protobuf_data
            }
            
            if frame.crc is not None:
                frame_data['crc'] = frame.crc
            if frame.crc_ok is not None:
                frame_data['crc_ok'] = frame.crc_ok
            
            data['frames'].append(frame_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return output_path
    
    def export_csv(self, output_path=None):
        if output_path is None:
            output_path = self.output_dir / f"{self.file_path.stem}.csv"
        
        import csv
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Frame', 'Offset', 'Size', 'Timestamp', 'Binary Objects', 'CRC'])
            
            for frame in self.frames:
                writer.writerow([
                    frame.index,
                    frame.offset,
                    frame.get_frame_size(),
                    frame.get_timestamp_str(),
                    len(frame.binary_objects),
                    frame.crc if frame.crc else 'N/A'
                ])
        
        return output_path
