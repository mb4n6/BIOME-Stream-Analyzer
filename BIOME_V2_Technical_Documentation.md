# BIOME Stream Version 2 - Technische Dokumentation

**Autor:** Marc Brandt (mb4n6)  
**Datum:** November 2024  
**Version:** 3.5.1

## Überblick

BIOME Stream Version 2 ist ein binäres Dateiformat, das auf iOS-Geräten für die Speicherung strukturierter Daten verwendet wird. Im Gegensatz zu Version 1 verwendet V2 ein Footer-basiertes Indexierungssystem mit CRC32-Prüfsummen zur Datenintegrität.

## Dateistruktur

```
┌─────────────────────────────────────────┐
│ Header (32 Bytes)                       │ Offset 0
├─────────────────────────────────────────┤
│ Frame 1                                 │ Offset 32 (BASE)
│  ├─ CRC32 (4 Bytes)                     │
│  ├─ Unknown (4 Bytes)                   │
│  └─ Protobuf Payload (Variable)        │
├─────────────────────────────────────────┤
│ Padding (0-15 Bytes, 0x00)              │
├─────────────────────────────────────────┤
│ Frame 2                                 │
│  ├─ CRC32 (4 Bytes)                     │
│  ├─ Unknown (4 Bytes)                   │
│  └─ Protobuf Payload (Variable)        │
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
│ Footer Entry 1 (16 Bytes)               │ Ende der Datei
└─────────────────────────────────────────┘
```

## Header-Format (32 Bytes)

```
Offset  Length  Typ        Beschreibung
------  ------  ---------  ---------------------------------------------
0x00    4       Magic      "SEGB" (0x53 45 47 42)
0x04    4       uint32     Unknown (oft 0x00000047)
0x08    8       double     Timestamp (Apple Epoch, CFAbsoluteTime)
0x10    4       uint32     Unknown (oft 0x0000000A)
0x14    12      bytes      Reserved/Unknown (oft 0xFF FF FF FF 00...)
```

## Footer-Format (16 Bytes pro Eintrag)

Footer-Einträge werden **von hinten nach vorne** gelesen und zeigen auf das Ende jedes Frames:

```
Offset  Length  Typ        Beschreibung
------  ------  ---------  ---------------------------------------------
0x00    4       uint32     Relativer Offset zum Frame-Ende (von BASE=32)
0x04    4       uint32     Unknown (meist 0x00000001)
0x08    8       double     Timestamp (Apple Epoch, CFAbsoluteTime)
```

## Frame-Struktur

Jeder Frame besteht aus:

### 1. Frame Header (8 Bytes)
```
Offset  Length  Typ        Beschreibung
------  ------  ---------  ---------------------------------------------
0x00    4       uint32     CRC32-Prüfsumme des Payloads
0x04    4       uint32     Unknown (meist 0x0000000B)
```

### 2. Protobuf Payload (Variable Länge)
Protocol Buffer serialisierte Daten mit verschiedenen Feldern.

### 3. Padding Bytes (0-15 Bytes)
Null-Bytes (0x00) zwischen Frames zur Ausrichtung.

## Frame-Berechnung Algorithmus

### Schritt 1: Footer-Pointer auslesen

Arbeite von der letzten Position der Datei rückwärts in 16-Byte-Schritten:

```python
BASE = 32  # Header-Größe
file_size = len(data)

entries = []
offset = file_size - 16

while offset >= BASE:
    chunk = data[offset:offset+16]
    
    # Überspringe leere Einträge
    if chunk == b'\x00' * 16:
        offset -= 16
        continue
    
    # Parse Footer-Eintrag
    end_rel, unknown, timestamp = struct.unpack('<IId', chunk)
    
    # Validierung
    if 0 < end_rel < (file_size - BASE):
        entries.append((offset, end_rel, unknown, timestamp))
    else:
        break  # Ende der Footer-Einträge erreicht
    
    offset -= 16

# Sortiere Einträge nach relativem Offset (aufsteigend)
entries.sort(key=lambda x: x[1])
```

### Schritt 2: Frame-Grenzen berechnen

Für jeden Footer-Eintrag:

```python
for idx, (footer_pos, end_rel, unknown, timestamp) in enumerate(entries):
    
    # Frame Start berechnen
    if idx == 0:
        # Erster Frame beginnt direkt nach Header
        frame_start = BASE  # = 32
    else:
        # Nachfolgende Frames: Ende des vorherigen + Padding
        prev_end_rel = entries[idx - 1][1]
        prev_frame_end = BASE + prev_end_rel
        
        # Padding-Bytes erkennen (0x00)
        padding = 0
        while data[prev_frame_end + padding] == 0:
            padding += 1
            if padding > 16:  # Sicherheitsprüfung
                break
        
        frame_start = prev_frame_end + padding
    
    # Frame Ende berechnen (OHNE Padding)
    frame_end = BASE + end_rel
    
    # Header auslesen (8 Bytes)
    crc32, unknown_field = struct.unpack('<II', 
                                          data[frame_start:frame_start+8])
    
    # Payload extrahieren
    payload_start = frame_start + 8
    payload = data[payload_start:frame_end]
    payload_length = len(payload)
```

### Schritt 3: CRC32-Validierung

```python
import zlib

# Berechne CRC32 des Payloads
calculated_crc = zlib.crc32(payload) & 0xFFFFFFFF

# Vergleiche mit Header-CRC32
crc_ok = (calculated_crc == crc32)
```

## Praktisches Beispiel

Beispiel aus Datei `743240128536818`:

### Footer-Pointer (letzte 16 Bytes)
```
Offset: 0x0FFFF0 (1048560)
Bytes:  0C 05 00 00 01 00 00 00 74 B6 44 E0 78 26 C6 41

Parsed:
  Relativer Offset: 0x0000050C = 1292 decimal
  Unknown:          0x00000001
  Timestamp:        743240128.536818 (2024-07-21 07:35:28.536 UTC)
```

### Frame 1 Berechnung

```
Footer-Offset:     1292 (relativ zu BASE=32)
Frame Start:       32 (erster Frame)
Frame Ende:        32 + 1292 = 1324
Payload Start:     32 + 8 = 40
Payload Ende:      1324
Payload Länge:     1284 bytes

Header Bytes (Offset 32-39):
  C7 CB C5 00 0B 00 00 00
  CRC32:    0xC7CBC500
  Unknown:  0x0000000B

Payload (Offset 40-1323):
  09 00 00 00 E0 78 26 C6 41 12 11 63 6F 6D 2E 61...
```

### Frame 2 Berechnung

```
Footer-Offset:     5798 (relativ zu BASE=32)
Frame Start:       1324 (Ende Frame 1, kein Padding)
Frame Ende:        32 + 5798 = 5830
Padding nach Frame: 2 bytes (0x00 0x00) → Tatsächliches Ende: 5832
Payload Start:     1324 + 8 = 1332
Payload Ende:      5830
Payload Länge:     4498 bytes

Header Bytes (Offset 1324-1331):
  73 4A 36 44 0B 00 00 00
  CRC32:    0x44364A73
  Unknown:  0x0000000B
```

### Frame 3 Berechnung

```
Footer-Offset:     10433 (relativ zu BASE=32)
Frame Start:       5832 (Ende Frame 2 + 2 Padding-Bytes)
Frame Ende:        32 + 10433 = 10465
Padding nach Frame: 3 bytes (0x00 0x00 0x00) → Tatsächliches Ende: 10468
Payload Start:     5832 + 8 = 5840
Payload Ende:      10465
Payload Länge:     4625 bytes
```

## Wichtige Hinweise

### Padding-Bytes

- Padding tritt zwischen Frames auf, nicht innerhalb
- Länge: 0-15 Bytes (typisch 0-3 Bytes)
- Wert: Immer 0x00
- Zweck: Wahrscheinlich Alignment für Performance

### Footer-Offset ist RELATIV

⚠️ **KRITISCH:** Der Offset im Footer ist **relativ zu Position 32** (BASE), nicht absolut!

```
❌ FALSCH:  frame_end = footer_offset
✓ RICHTIG: frame_end = BASE + footer_offset
           frame_end = 32 + footer_offset
```

### CRC32-Berechnung

```python
import zlib

# CRC32 wird nur über den Payload berechnet (ohne Header!)
crc32_value = zlib.crc32(payload) & 0xFFFFFFFF
```

### Timestamp-Format

Apple CFAbsoluteTime (Sekunden seit 01.01.2001 00:00:00 UTC):

```python
from datetime import datetime, timezone, timedelta

APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

def apple_time_to_datetime(timestamp):
    return APPLE_EPOCH + timedelta(seconds=timestamp)
```

## Protobuf-Payload Analyse

Die Payloads enthalten Protocol Buffer-Daten. Typische Felder:

### Field IDs (häufig vorkommend)

```
field_1:  Timestamp (double)
field_2:  Bundle Identifier (string) z.B. "com.apple.mobilesafari"
field_3:  Stream Identifier (string)
field_4:  Protobuf-verschachtelt (weitere Daten)
```

### Beispiel-Dekodierung

```
Bytes: 09 00 00 00 E0 78 26 C6 41 12 11 63 6F 6D 2E 61...

09          → Wire Type 1 (fixed64), Field ID 1
00 00 00 E0 78 26 C6 41 → Double: 743240128.536818

12          → Wire Type 2 (length-delimited), Field ID 2
11          → Länge: 17 bytes
63 6F 6D... → String: "com.apple.mobilesafari"
```

## Fehlerbehandlung

### Validierungen

1. **Header-Magic prüfen:** Muss "SEGB" (0x53454742) sein
2. **Footer-Offset Validierung:** `0 < offset < (file_size - 32)`
3. **Frame-Grenzen prüfen:** `frame_start + 8 < frame_end`
4. **CRC32 verifizieren:** Payload-Integrität sicherstellen
5. **Padding-Limit:** Maximal 16 Bytes Padding zwischen Frames

### Fehlertoleranz

Bei fehlerhaften Frames:
- Überspringe Frame, fahre mit nächstem fort
- CRC-Fehler protokollieren, aber nicht abbrechen
- Padding-Anomalien (>16 Bytes) → Warnung, aber weiter parsen

## Parser-Implementierung

Siehe `biome_core.py` Klasse `BIOMEAnalyzer._analyze_v2()` für Referenz-Implementierung.

### Schlüssel-Algorithmus

```python
def parse_biome_v2(file_path):
    BASE = 32
    data = open(file_path, 'rb').read()
    
    # 1. Header validieren
    if data[:4] != b'SEGB':
        raise ValueError("Invalid BIOME V2 file")
    
    # 2. Footer-Einträge sammeln
    entries = []
    offset = len(data) - 16
    while offset >= BASE:
        end_rel, unk, ts = struct.unpack('<IId', data[offset:offset+16])
        if 0 < end_rel < len(data) - BASE:
            entries.append((offset, end_rel, unk, ts))
        offset -= 16
    
    # 3. Sortieren nach Offset
    entries.sort(key=lambda x: x[1])
    
    # 4. Frames extrahieren
    frames = []
    for idx, (_, end_rel, _, ts) in enumerate(entries):
        # Start berechnen
        if idx == 0:
            start = BASE
        else:
            prev_end = BASE + entries[idx-1][1]
            padding = 0
            while data[prev_end + padding] == 0:
                padding += 1
            start = prev_end + padding
        
        # Ende berechnen
        end = BASE + end_rel
        
        # Header + Payload
        crc32 = struct.unpack('<I', data[start:start+4])[0]
        payload = data[start+8:end]
        
        # CRC validieren
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
| **Indexierung**      | Frame-Header basiert    | Footer-basiert               |
| **Integrität**       | Keine Prüfsummen        | CRC32 pro Frame              |
| **Frame-Suche**      | Sequenziell scannen     | Direkter Zugriff via Footer  |
| **Padding**          | 8-Byte Alignment        | Variable (0-15 Bytes)        |
| **Timestamps**       | Im Frame-Header         | Im Footer-Eintrag            |
| **Effizienz**        | Langsam bei großen Files| Schnell, indexiert           |

## Tools

### BIOME Analyzer

```bash
# Alle Frames analysieren
python3 biome_analyzer.py datei.biome --frames all --verbose

# Mit HTML-Report
python3 biome_analyzer.py datei.biome -o output/

# GUI-Modus
python3 biome_analyzer.py --gui
```

### Export-Formate

- **JSON:** Strukturierte Daten mit Protobuf-Feldern
- **CSV:** Tabelle mit Frame-Metadaten
- **HTML:** Interaktiver Report mit Visualisierungen

## Forensische Relevanz

BIOME Streams enthalten wichtige Aktivitätsdaten:
- Browser-Historie (Safari)
- App-Nutzung
- Systemereignisse
- Geräte-Interaktionen

**Wichtig für Forensik:**
- Timestamps sind in UTC (Apple Epoch)
- CRC32-Prüfsummen können Manipulationen aufdecken
- Gelöschte Daten können in ungenutzten Bereichen vorhanden sein

## Zusammenfassung

Die BIOME Stream Version 2 nutzt ein **Footer-basiertes Indexsystem** mit CRC32-Integritätsprüfung. Die korrekte Berechnung der Frame-Positionen erfordert:

1. **Footer von hinten nach vorne lesen**
2. **Offsets sind RELATIV zu Position 32**
3. **Padding-Bytes zwischen Frames erkennen**
4. **CRC32 über Payload (ohne Header) berechnen**

Mit diesem Wissen können forensische Analysten BIOME V2-Dateien vollständig und korrekt parsen.

---

**Lizenz:** Für forensische und educational Zwecke  
**Kontakt:** Marc Brandt (mb4n6)
