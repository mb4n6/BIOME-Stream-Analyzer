#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
from biome_core import BIOMEAnalyzer

def main():
    parser = argparse.ArgumentParser(description='BIOME Stream Analyzer v1/v2')
    parser.add_argument('file', help='BIOME stream file')
    parser.add_argument('--frames', default='5', help='Max frames (number or "all")')
    parser.add_argument('--version', type=int, choices=[1, 2], help='Force version')
    parser.add_argument('--min-binary-size', type=int, default=100, help='Min binary size (bytes)')
    parser.add_argument('--output-dir', '-o', help='Output directory for reports (default: same as input file)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--full', action='store_true', default=True, help='Full protobuf values')
    parser.add_argument('--no-html', action='store_true', help='Skip HTML report')
    parser.add_argument('--gui', action='store_true', help='Launch GUI instead of CLI')
    args = parser.parse_args()
    
    if args.gui:
        try:
            import tkinter as tk
            from biome_gui import BiomeGUI
            root = tk.Tk()
            app = BiomeGUI(root)
            root.mainloop()
            return 0
        except ImportError:
            print("Error: tkinter not available")
            return 1
    
    print("="*60)
    print("BIOME Stream Analyzer v3.5.1")
    print("Author: Marc Brandt (mb4n6)")
    print("="*60)
    
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: File not found: {args.file}")
        return 1
    
    max_frames = float('inf') if args.frames.lower() == 'all' else int(args.frames)
    print(f"File: {file_path.name} ({file_path.stat().st_size:,} bytes)")
    print(f"Frames: {max_frames if max_frames != float('inf') else 'ALL'}")
    print("-"*60)
    
    try:
        analyzer = BIOMEAnalyzer(
            str(file_path),
            max_frames=max_frames,
            verbose=args.verbose,
            full_output=args.full,
            min_binary_size=args.min_binary_size,
            force_version=args.version,
            output_dir=args.output_dir
        )
        
        if not analyzer.analyze():
            print("Analysis failed!")
            return 1
        
        print(f"\nVersion: {analyzer.version}")
        print(f"Frames: {len(analyzer.frames)}")
        print(f"Binary objects: {sum(len(f.binary_objects) for f in analyzer.frames)}")
        print(f"Hash: {analyzer.file_hash}")
        print(f"\nOutput directory: {analyzer.output_dir}")
        
        json_path = analyzer.export_json()
        csv_path = analyzer.export_csv()
        print(f"✓ JSON: {json_path.name}")
        print(f"✓ CSV: {csv_path.name}")
        
        if not args.no_html:
            from biome_reports import HTMLReport
            html_path = HTMLReport(analyzer).generate()
            print(f"✓ HTML: {html_path.name}")
        
        print("="*60)
        return 0
        
    except KeyboardInterrupt:
        print("\nInterrupted")
        return 130
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
