# BIOME Stream Analyzer

Forensic analysis tool for iOS BIOME stream files (v1 and v2 formats).

## Features

- **Dual Format Support**: Analyzes BIOME v1 and v2 stream structures
- **Binary Object Detection**: Automatically identifies embedded images, plists, and other binary data
- **Protobuf Analysis**: Parses and displays protobuf field data
- **Interactive GUI**: User-friendly interface with result viewer
- **Multiple Export Formats**: JSON, CSV, and comprehensive HTML reports
- **Hex Viewer**: Built-in hex dump for detailed inspection
- **Plist Viewer**: Hierarchical view with automatic binary plist parsing

## Installation

```bash
# Clone repository
git clone https://github.com/mb4n6/biome-analyzer.git
cd biome-analyzer

# Install dependencies
pip install pillow --break-system-packages  # Optional: for image viewing
```

## Usage

### GUI Version
```bash
python biome_gui.py
```

### Command Line
```bash
# Analyze file with default settings (5 frames)
python biome_analyzer.py file.biome

# Analyze all frames
python biome_analyzer.py file.biome --frames all

# Specify output directory
python biome_analyzer.py file.biome --output-dir ./reports

# Verbose output
python biome_analyzer.py file.biome --frames 100 -v

# GUI Mode
python biome_analyzer.py --gui
```

### Options
```
--frames N          Max frames to analyze (number or "all")
--output-dir DIR    Output directory for reports
--version {1,2}     Force specific BIOME version
--min-binary-size N Minimum binary object size (default: 100)
--no-html           Skip HTML report generation
--verbose, -v       Verbose output
--gui               Launch GUI mode
```

## Output Files

- `filename.json` - Complete analysis in JSON format
- `filename.csv` - Frame summary in CSV format
- `filename.html` - Interactive HTML report with viewers

## BIOME Format Support

### Version 1
- 32-byte frame headers with timestamps
- CRC validation
- 4096-byte frame alignment

### Version 2
- SEGB magic header
- Footer-based frame indexing
- Variable-length frames with CRC32

## Educational Use

Includes `biome-forensics.html` documentation covering:
- BIOME stream structure (v1 and v2)
- Frame format specifications
- Forensic analysis techniques
- Binary object identification

Access via GUI: **Help → Learn: BIOME Forensics**

## Requirements

- Python 3.8+
- tkinter (usually included with Python)
- Pillow (optional, for image viewing)

## Author

**Marc Brandt (mb4n6)**

## License

MIT License - See LICENSE file for details

## Version

Current: v3.5.5
