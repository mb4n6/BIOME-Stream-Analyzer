#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
import webbrowser
from biome_core import BIOMEAnalyzer
from biome_reports import HTMLReport

class BiomeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BIOME Analyzer v3.5")
        self.root.geometry("900x650")
        
        self.selected_file = tk.StringVar()
        self.output_dir = tk.StringVar(value="")
        self.max_frames = tk.StringVar(value="100")
        self.verbose = tk.BooleanVar(value=False)
        self.analyzer = None
        
        self._build_ui()
        self._create_menu()
    
    def _build_ui(self):
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill="x")
        
        ttk.Label(top_frame, text="BIOME File:").pack(side="left")
        ttk.Entry(top_frame, textvariable=self.selected_file, width=60).pack(side="left", padx=5)
        ttk.Button(top_frame, text="Browse", command=self._browse).pack(side="left")
        
        output_frame = ttk.Frame(self.root, padding="10")
        output_frame.pack(fill="x")
        
        ttk.Label(output_frame, text="Output Dir:").pack(side="left")
        ttk.Entry(output_frame, textvariable=self.output_dir, width=60).pack(side="left", padx=5)
        ttk.Button(output_frame, text="Browse", command=self._browse_output).pack(side="left", padx=2)
        ttk.Button(output_frame, text="Clear", command=lambda: self.output_dir.set("")).pack(side="left")
        
        opts_frame = ttk.Frame(self.root, padding="10")
        opts_frame.pack(fill="x")
        
        ttk.Label(opts_frame, text="Max Frames:").pack(side="left")
        ttk.Combobox(opts_frame, textvariable=self.max_frames, 
                    values=["5", "10", "50", "100", "all"], width=8).pack(side="left", padx=5)
        ttk.Checkbutton(opts_frame, text="Verbose", variable=self.verbose).pack(side="left", padx=10)
        
        btn_frame = ttk.Frame(self.root, padding="10")
        btn_frame.pack(fill="x")
        
        ttk.Button(btn_frame, text="Analyze", command=self._analyze, width=15).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="View Results", command=self._view_results, width=15).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Open HTML Report", command=self._open_html, width=18).pack(side="left", padx=5)
        
        self.log_text = scrolledtext.ScrolledText(self.root, height=25, font=("Courier", 9))
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.status = ttk.Label(self.root, text="Ready", relief="sunken")
        self.status.pack(fill="x", side="bottom")
    
    def _browse(self):
        path = filedialog.askopenfilename(title="Select BIOME file", filetypes=[("All files", "*.*")])
        if path:
            self.selected_file.set(path)
    
    def _browse_output(self):
        path = filedialog.askdirectory(title="Select Output Directory")
        if path:
            self.output_dir.set(path)
    
    def _create_menu(self):
        """Create menu bar with Help option"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open BIOME File...", command=self._browse)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="📚 Learn: BIOME Forensics", command=self._show_help)
        help_menu.add_command(label="About", command=self._show_about)
    
    def _show_about(self):
        """Show about dialog"""
        messagebox.showinfo("About BIOME Analyzer",
            "BIOME Stream Analyzer v3.5\n\n"
            "Forensic analysis tool for iOS BIOME stream files.\n\n"
            "Author: Marc Brandt (mb4n6)\n"
            "License: MIT\n\n"
            "Supports BIOME v1 and v2 formats with comprehensive\n"
            "binary object detection and protobuf analysis.")
    
    def _show_help(self):
        """Open BIOME forensics documentation in browser"""
        import webbrowser
        from pathlib import Path
        
        # Look for biome-forensics.html in same directory as script
        script_dir = Path(__file__).parent
        help_file = script_dir / "biome-forensics.html"
        
        if help_file.exists():
            webbrowser.open(help_file.as_uri())
        else:
            # Try current directory
            help_file = Path("biome-forensics.html")
            if help_file.exists():
                webbrowser.open(help_file.as_uri())
            else:
                messagebox.showwarning("Help Not Found",
                    "BIOME forensics documentation (biome-forensics.html) not found.\n\n"
                    "Please ensure biome-forensics.html is in the same directory as the script.")

    
    def _log(self, msg):
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.root.update()
    
    def _analyze(self):
        path = self.selected_file.get()
        if not path or not Path(path).exists():
            messagebox.showerror("Error", "Please select a valid BIOME file")
            return
        
        self.log_text.delete("1.0", "end")
        self._log(f"Analyzing: {Path(path).name}")
        self.status.config(text="Analyzing...")
        
        try:
            mf = self.max_frames.get()
            max_frames = float('inf') if mf == 'all' else int(mf)
            
            # Use selected output directory or default to file's directory
            output_dir = self.output_dir.get() if self.output_dir.get() else None
            
            self.analyzer = BIOMEAnalyzer(
                path,
                max_frames=max_frames,
                verbose=self.verbose.get(),
                full_output=True,
                min_binary_size=100,
                output_dir=output_dir
            )
            
            if not self.analyzer.analyze():
                self._log("❌ Analysis failed")
                self.status.config(text="Failed")
                return
            
            self._log(f"✓ Version: {self.analyzer.version}")
            self._log(f"✓ Frames: {len(self.analyzer.frames)}")
            self._log(f"✓ Binary objects: {sum(len(f.binary_objects) for f in self.analyzer.frames)}")
            self._log(f"✓ Hash: {self.analyzer.file_hash[:32]}...")
            
            json_path = self.analyzer.export_json()
            csv_path = self.analyzer.export_csv()
            html_path = HTMLReport(self.analyzer).generate()
            
            self._log(f"✓ Reports generated in: {self.analyzer.output_dir}")
            self._log(f"  - {json_path.name}")
            self._log(f"  - {csv_path.name}")
            self._log(f"  - {html_path.name}")
            
            self.status.config(text="Analysis complete")
            messagebox.showinfo("Success", "Analysis completed successfully!")
            
        except Exception as e:
            self._log(f"❌ Error: {e}")
            self.status.config(text="Error")
            messagebox.showerror("Error", str(e))
    
    def _view_results(self):
        if not self.analyzer or not self.analyzer.frames:
            messagebox.showinfo("Info", "Please run analysis first")
            return
        
        ResultsViewer(self.root, self.analyzer)
    
    def _open_html(self):
        if not self.analyzer:
            messagebox.showinfo("Info", "Please run analysis first")
            return
        
        html_path = self.analyzer.output_dir / f"{Path(self.analyzer.file_path).stem}.html"
        if html_path.exists():
            webbrowser.open(html_path.as_uri())
        else:
            messagebox.showerror("Error", "HTML report not found")

class ResultsViewer(tk.Toplevel):
    def __init__(self, parent, analyzer):
        super().__init__(parent)
        self.analyzer = analyzer
        self.current_idx = 0
        
        self.title(f"BIOME Results - {Path(analyzer.file_path).name}")
        self.geometry("1200x800")
        
        self._build_ui()
        self._show_frame(0)
    
    def _build_ui(self):
        header = ttk.Frame(self, padding="10")
        header.pack(fill="x")
        
        ttk.Label(header, text=f"Version: {self.analyzer.version} | Frames: {len(self.analyzer.frames)} | "
                 f"Binary Objects: {sum(len(f.binary_objects) for f in self.analyzer.frames)}", 
                 font=("Arial", 11, "bold")).pack()
        
        nav = ttk.Frame(self, padding="10")
        nav.pack(fill="x")
        
        ttk.Button(nav, text="◀ Previous", command=self._prev_frame, width=12).pack(side="left", padx=5)
        self.frame_label = ttk.Label(nav, text="", font=("Arial", 10))
        self.frame_label.pack(side="left", padx=20)
        ttk.Button(nav, text="Next ▶", command=self._next_frame, width=12).pack(side="left", padx=5)
        
        ttk.Separator(self, orient="horizontal").pack(fill="x", pady=5)
        
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        info_frame = ttk.Frame(notebook, padding="10")
        notebook.add(info_frame, text="Frame Info")
        
        self.info_text = scrolledtext.ScrolledText(info_frame, height=10, font=("Courier", 9))
        self.info_text.pack(fill="both", expand=True)
        
        binary_frame = ttk.Frame(notebook, padding="10")
        notebook.add(binary_frame, text="Binary Objects")
        
        bin_controls = ttk.Frame(binary_frame)
        bin_controls.pack(fill="x", pady=(0, 10))
        ttk.Label(bin_controls, text="Double-click to open • Right-click for options", 
                 font=("Arial", 9, "italic")).pack(side="left")
        
        self.binary_tree = ttk.Treeview(binary_frame, columns=("Type", "Size", "Entropy", "Offset"), show="headings", height=15)
        self.binary_tree.heading("Type", text="Type")
        self.binary_tree.heading("Size", text="Size")
        self.binary_tree.heading("Entropy", text="Entropy")
        self.binary_tree.heading("Offset", text="Offset")
        self.binary_tree.column("Type", width=200)
        self.binary_tree.column("Size", width=100)
        self.binary_tree.column("Entropy", width=80)
        self.binary_tree.column("Offset", width=100)
        
        self.binary_tree.bind("<Double-1>", self._on_binary_object_double_click)
        self.binary_tree.bind("<Button-3>", self._on_binary_object_right_click)
        
        scrollbar = ttk.Scrollbar(binary_frame, orient="vertical", command=self.binary_tree.yview)
        self.binary_tree.configure(yscrollcommand=scrollbar.set)
        
        self.binary_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        protobuf_frame = ttk.Frame(notebook, padding="10")
        notebook.add(protobuf_frame, text="Protobuf Data")
        
        self.protobuf_text = scrolledtext.ScrolledText(protobuf_frame, height=20, font=("Courier", 9))
        self.protobuf_text.pack(fill="both", expand=True)
        
        hex_frame = ttk.Frame(notebook, padding="10")
        notebook.add(hex_frame, text="Hex Preview")
        
        self.hex_text = scrolledtext.ScrolledText(hex_frame, height=30, font=("Courier", 9))
        self.hex_text.pack(fill="both", expand=True)
    
    def _show_frame(self, idx):
        if idx < 0 or idx >= len(self.analyzer.frames):
            return
        
        self.current_idx = idx
        frame = self.analyzer.frames[idx]
        
        self.frame_label.config(text=f"Frame {idx + 1} / {len(self.analyzer.frames)}")
        
        self.info_text.delete("1.0", "end")
        self.info_text.insert("end", f"Frame Index: {frame.index}\n")
        self.info_text.insert("end", f"Version: {frame.version}\n")
        self.info_text.insert("end", f"Offset: 0x{frame.offset:08X} ({frame.offset:,} bytes)\n" if frame.offset else "Offset: N/A\n")
        self.info_text.insert("end", f"Size: {frame.get_frame_size():,} bytes\n")
        self.info_text.insert("end", f"Timestamp: {frame.get_timestamp_str()}\n")
        
        if frame.crc is not None:
            crc_status = "✓ OK" if frame.crc_ok else "✗ FAILED"
            self.info_text.insert("end", f"CRC32: 0x{frame.crc:08X} {crc_status}\n")
        
        self.info_text.insert("end", f"Binary Objects: {len(frame.binary_objects)}\n")
        self.info_text.insert("end", f"File Hash: {frame.file_hash}\n")
        
        for item in self.binary_tree.get_children():
            self.binary_tree.delete(item)
        
        for obj in frame.binary_objects:
            self.binary_tree.insert("", "end", values=(
                obj.get('type', 'Unknown'),
                f"{obj.get('size', 0):,}",
                f"{obj.get('entropy', 0):.2f}",
                f"0x{obj.get('offset', 0):X}"
            ))
        
        self.protobuf_text.delete("1.0", "end")
        if frame.protobuf_data:
            self.protobuf_text.insert("end", f"Protobuf Fields: {len(frame.protobuf_data)}\n")
            self.protobuf_text.insert("end", "=" * 80 + "\n\n")
            
            for key, value in sorted(frame.protobuf_data.items()):
                value_str = str(value)
                if len(value_str) > 500:
                    value_str = value_str[:500] + '...'
                self.protobuf_text.insert("end", f"{key}:\n")
                self.protobuf_text.insert("end", f"  {value_str}\n\n")
        else:
            self.protobuf_text.insert("end", "No Protobuf data found in this frame")
        
        self.hex_text.delete("1.0", "end")
        if frame.payload and len(frame.payload) > 0:
            hex_lines = []
            for i in range(0, min(len(frame.payload), 2048), 16):
                chunk = frame.payload[i:i+16]
                hex_part = " ".join(f"{b:02X}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                hex_lines.append(f"{i:08X}  {hex_part:<48}  {ascii_part}")
            
            self.hex_text.insert("end", "\n".join(hex_lines))
            if len(frame.payload) > 2048:
                self.hex_text.insert("end", f"\n\n... ({len(frame.payload) - 2048} more bytes)")
        else:
            self.hex_text.insert("end", "No payload data available")
    
    def _prev_frame(self):
        if self.current_idx > 0:
            self._show_frame(self.current_idx - 1)
    
    def _next_frame(self):
        if self.current_idx < len(self.analyzer.frames) - 1:
            self._show_frame(self.current_idx + 1)
    
    def _on_binary_object_double_click(self, event):
        selection = self.binary_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = self.binary_tree.item(item, 'values')
        obj_type = values[0]
        
        frame = self.analyzer.frames[self.current_idx]
        item_idx = self.binary_tree.index(item)
        
        if item_idx < len(frame.binary_objects):
            obj = frame.binary_objects[item_idx]
            self._open_binary_object(obj, obj_type, frame)
    
    def _on_binary_object_right_click(self, event):
        item = self.binary_tree.identify_row(event.y)
        if item:
            self.binary_tree.selection_set(item)
            menu = tk.Menu(self, tearoff=0)
            
            values = self.binary_tree.item(item, 'values')
            obj_type = values[0]
            
            if obj_type in ['JPEG', 'PNG', 'GIF87a', 'GIF89a', 'Bitmap', 'ICO']:
                menu.add_command(label="🖼️ View Image", command=lambda: self._on_binary_object_double_click(None))
            elif obj_type == 'Binary PLIST':
                menu.add_command(label="📋 View Plist", command=lambda: self._on_binary_object_double_click(None))
            
            menu.add_command(label="🔍 Hex View", command=self._view_hex_from_selection)
            menu.add_command(label="💾 Export to File", command=self._export_binary_object)
            
            menu.post(event.x_root, event.y_root)
    
    def _open_binary_object(self, obj, obj_type, frame):
        offset = obj.get('offset', 0)
        size = obj.get('size', 0)
        
        if not frame.payload or offset + size > len(frame.payload):
            messagebox.showerror("Error", "Object data not available")
            return
        
        data = frame.payload[offset:offset+size]
        
        if obj_type in ['JPEG', 'PNG', 'GIF87a', 'GIF89a', 'Bitmap', 'ICO']:
            self._view_image(data, obj_type)
        elif obj_type == 'Binary PLIST':
            self._view_plist(data)
        else:
            self._view_hex_dialog(data, obj_type)
    
    def _view_image(self, data, obj_type):
        try:
            from PIL import Image, ImageTk
            import io
            
            img = Image.open(io.BytesIO(data))
            
            viewer = tk.Toplevel(self)
            viewer.title(f"Image Viewer - {obj_type}")
            viewer.geometry("800x600")
            
            max_size = (750, 550)
            img.thumbnail(max_size, Image.Resampling.LANCZOS)
            
            photo = ImageTk.PhotoImage(img)
            
            label = ttk.Label(viewer, image=photo)
            label.image = photo
            label.pack(expand=True)
            
            info = ttk.Label(viewer, text=f"Size: {img.size[0]}x{img.size[1]} | Mode: {img.mode}")
            info.pack(pady=5)
            
        except ImportError:
            messagebox.showinfo("PIL Required", "Install Pillow to view images:\npip install Pillow")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open image: {e}")
    
    def _view_plist(self, data):
        viewer = tk.Toplevel(self)
        viewer.title("Plist Viewer")
        viewer.geometry("800x600")
        
        # Create notebook for tabs
        notebook = ttk.Notebook(viewer)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Tab 1: Parsed view
        parsed_frame = ttk.Frame(notebook)
        notebook.add(parsed_frame, text="Parsed")
        
        parsed_text = scrolledtext.ScrolledText(parsed_frame, font=("Courier", 10), wrap="word")
        parsed_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Tab 2: Raw hex view
        hex_frame = ttk.Frame(notebook)
        notebook.add(hex_frame, text="Hex View")
        
        hex_text = scrolledtext.ScrolledText(hex_frame, font=("Courier", 9), wrap="none")
        hex_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Try multiple parsing strategies
        parsed_successfully = False
        
        try:
            import plistlib
            import json
            
            # Clean data first - strip leading nulls if present
            clean_data = data.lstrip(b'\x00')
            
            # Strategy 1: Try standard plistlib on original data
            for attempt_data in [data, clean_data]:
                if not attempt_data:
                    continue
                    
                try:
                    plist = plistlib.loads(attempt_data)
                    parsed_text.insert("1.0", json.dumps(plist, indent=2, default=str, ensure_ascii=False))
                    parsed_successfully = True
                    break
                except Exception as e1:
                    # Strategy 2: Try with different formats
                    try:
                        plist = plistlib.loads(attempt_data, fmt=plistlib.FMT_BINARY)
                        parsed_text.insert("1.0", json.dumps(plist, indent=2, default=str, ensure_ascii=False))
                        parsed_successfully = True
                        break
                    except:
                        continue
            
            if not parsed_successfully:
                # Show diagnostic info
                has_leading_zeros = data[:4] == b'\x00\x00\x00\x00'
                bplist_offset = data.find(b'bplist')
                
                parsed_text.insert("1.0", "Binary plist detected but parsing failed:\n\n")
                
                if has_leading_zeros:
                    parsed_text.insert("end", f"⚠️  File has {len(data) - len(data.lstrip(b'\\x00'))} leading null bytes\n")
                    parsed_text.insert("end", "   This is non-standard and may indicate file corruption.\n\n")
                
                if bplist_offset > 0:
                    parsed_text.insert("end", f"ℹ️  bplist header found at offset {bplist_offset}\n\n")
                
                # Check for NSKeyedArchiver
                if b'NSKeyedArchiver' in data[:200] or b'$archiver' in data[:200]:
                    parsed_text.insert("end", "📦 NSKeyedArchiver format detected\n")
                    parsed_text.insert("end", "   This is a serialized Objective-C object.\n\n")
                
                parsed_text.insert("end", "Please check the Hex View tab for raw data.\n\n")
                parsed_text.insert("end", f"Header (hex): {data[:16].hex()}\n")
                parsed_text.insert("end", f"File size: {len(data)} bytes\n\n")
                
                # If cleaned data is different, show info
                if len(clean_data) != len(data):
                    parsed_text.insert("end", f"After removing leading zeros: {len(clean_data)} bytes\n")
                    parsed_text.insert("end", f"Clean header: {clean_data[:16].hex()}\n\n")
                
                parsed_text.insert("end", "Possible issues:\n")
                parsed_text.insert("end", "• File may be corrupted or incomplete\n")
                parsed_text.insert("end", "• Non-standard plist format\n")
                parsed_text.insert("end", "• Extracted from a larger binary (with padding)\n")
                parsed_text.insert("end", "• May require special decoder for NSKeyedArchiver\n")
        
        except ImportError:
            parsed_text.insert("1.0", "plistlib module not available")
        
        # Always show hex view
        hex_lines = []
        for i in range(0, min(len(data), 32768), 16):  # Limit to 32KB for performance
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_lines.append(f"{i:08X}  {hex_part:<48}  {ascii_part}")
        
        hex_text.insert("1.0", "\n".join(hex_lines))
        if len(data) > 32768:
            hex_text.insert("end", f"\n\n... ({len(data) - 32768} more bytes, truncated for display)")
        
        hex_text.config(state="disabled")
        if parsed_successfully:
            parsed_text.config(state="disabled")
        
        # Select appropriate tab
        notebook.select(0 if parsed_successfully else 1)
    
    def _view_hex_dialog(self, data, obj_type):
        viewer = tk.Toplevel(self)
        viewer.title(f"Hex Viewer - {obj_type}")
        viewer.geometry("900x600")
        
        text = scrolledtext.ScrolledText(viewer, font=("Courier", 9))
        text.pack(fill="both", expand=True, padx=10, pady=10)
        
        hex_lines = []
        for i in range(0, min(len(data), 16384), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_lines.append(f"{i:08X}  {hex_part:<48}  {ascii_part}")
        
        text.insert("1.0", "\n".join(hex_lines))
        if len(data) > 16384:
            text.insert("end", f"\n\n... ({len(data) - 16384} more bytes)")
        
        text.config(state="disabled")
    
    def _view_hex_from_selection(self):
        selection = self.binary_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        item_idx = self.binary_tree.index(item)
        frame = self.analyzer.frames[self.current_idx]
        
        if item_idx < len(frame.binary_objects):
            obj = frame.binary_objects[item_idx]
            obj_type = obj.get('type', 'Unknown')
            offset = obj.get('offset', 0)
            size = obj.get('size', 0)
            
            if frame.payload and offset + size <= len(frame.payload):
                data = frame.payload[offset:offset+size]
                self._view_hex_dialog(data, obj_type)
    
    def _export_binary_object(self):
        selection = self.binary_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        item_idx = self.binary_tree.index(item)
        frame = self.analyzer.frames[self.current_idx]
        
        if item_idx < len(frame.binary_objects):
            obj = frame.binary_objects[item_idx]
            obj_type = obj.get('type', 'Unknown')
            offset = obj.get('offset', 0)
            size = obj.get('size', 0)
            
            if not frame.payload or offset + size > len(frame.payload):
                messagebox.showerror("Error", "Object data not available")
                return
            
            ext_map = {
                'JPEG': '.jpg',
                'PNG': '.png',
                'GIF87a': '.gif',
                'GIF89a': '.gif',
                'Binary PLIST': '.plist',
                'PDF': '.pdf',
                'ZIP': '.zip'
            }
            ext = ext_map.get(obj_type, '.bin')
            
            filename = filedialog.asksaveasfilename(
                defaultextension=ext,
                filetypes=[("All files", "*.*")],
                initialfile=f"frame{frame.index}_obj{item_idx}{ext}"
            )
            
            if filename:
                try:
                    data = frame.payload[offset:offset+size]
                    with open(filename, 'wb') as f:
                        f.write(data)
                    messagebox.showinfo("Success", f"Exported to {Path(filename).name}")
                except Exception as e:
                    messagebox.showerror("Error", f"Export failed: {e}")

def main():
    root = tk.Tk()
    app = BiomeGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
