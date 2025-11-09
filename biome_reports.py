#!/usr/bin/env python3
import html
import base64
from datetime import datetime
from pathlib import Path

class HTMLReport:
    def __init__(self, analyzer):
        self.analyzer = analyzer
    
    def generate(self, output_path=None):
        if output_path is None:
            output_path = self.analyzer.output_dir / f"{self.analyzer.file_path.stem}.html"
        
        html_content = self._build_html()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def _get_file_extension(self, obj_type):
        ext_map = {
            'JPEG': 'jpg',
            'PNG': 'png',
            'GIF87a': 'gif',
            'GIF89a': 'gif',
            'Binary PLIST': 'plist',
            'PDF': 'pdf',
            'ZIP': 'zip'
        }
        return ext_map.get(obj_type, 'bin')
    
    def _build_html(self):
        frames_html = "\n".join(self._frame_html(f, idx) for idx, f in enumerate(self.analyzer.frames))
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>BIOME Analysis Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.9; font-size: 14px; }}
        .summary {{ padding: 30px; background: #f8f9fa; border-bottom: 1px solid #dee2e6; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
        .summary-item {{ background: white; padding: 20px; border-radius: 6px; border-left: 4px solid #667eea; }}
        .summary-item .label {{ color: #6c757d; font-size: 12px; text-transform: uppercase; margin-bottom: 5px; }}
        .summary-item .value {{ font-size: 24px; font-weight: bold; color: #212529; }}
        .frames {{ padding: 30px; }}
        .frame {{ background: white; border: 1px solid #dee2e6; border-radius: 6px; margin-bottom: 20px; overflow: hidden; }}
        .frame-header {{ background: #f8f9fa; padding: 15px 20px; border-bottom: 1px solid #dee2e6; display: flex; justify-content: space-between; align-items: center; }}
        .frame-header h3 {{ color: #495057; font-size: 18px; }}
        .frame-info {{ font-size: 13px; color: #6c757d; }}
        .frame-body {{ padding: 20px; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .info-item {{ display: flex; justify-content: space-between; padding: 8px 12px; background: #f8f9fa; border-radius: 4px; }}
        .info-label {{ font-weight: 600; color: #495057; }}
        .info-value {{ color: #6c757d; }}
        .binary-objects {{ margin-top: 20px; }}
        .binary-objects h4 {{ color: #495057; margin-bottom: 15px; font-size: 16px; }}
        .binary-object {{ background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; padding: 15px; margin-bottom: 10px; position: relative; }}
        .binary-object .type {{ font-weight: bold; color: #856404; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; }}
        .binary-object .controls {{ margin-top: 10px; display: flex; gap: 8px; flex-wrap: wrap; }}
        .binary-object .controls button {{ padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 500; transition: all 0.2s; }}
        .btn-view {{ background: #007bff; color: white; }}
        .btn-view:hover {{ background: #0056b3; }}
        .btn-hex {{ background: #6c757d; color: white; }}
        .btn-hex:hover {{ background: #545b62; }}
        .btn-download {{ background: #28a745; color: white; }}
        .btn-download:hover {{ background: #218838; }}
        .hex-preview {{ font-family: 'Courier New', monospace; font-size: 11px; background: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; white-space: pre; color: #212529; margin-top: 10px; }}
        .viewer-modal {{ display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.85); }}
        .viewer-content {{ background-color: #fefefe; margin: 2% auto; padding: 20px; border: 1px solid #888; border-radius: 8px; width: 90%; max-width: 1200px; max-height: 90vh; overflow: auto; }}
        .viewer-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #dee2e6; }}
        .viewer-header h3 {{ color: #333; margin: 0; }}
        .close-btn {{ color: #aaa; font-size: 32px; font-weight: bold; cursor: pointer; line-height: 1; }}
        .close-btn:hover {{ color: #000; }}
        .plist-viewer {{ font-family: 'Courier New', monospace; font-size: 13px; background: #f8f9fa; padding: 15px; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; max-height: 70vh; overflow: auto; }}
        .plist-tree {{ font-family: 'SF Mono', 'Monaco', 'Courier New', monospace; font-size: 13px; background: #ffffff; padding: 15px; border-radius: 4px; max-height: 70vh; overflow: auto; line-height: 1.6; }}
        .plist-node {{ margin-left: 20px; }}
        .plist-key {{ color: #0066cc; font-weight: 600; cursor: pointer; user-select: none; }}
        .plist-key:hover {{ text-decoration: underline; }}
        .plist-string {{ color: #008000; }}
        .plist-number {{ color: #0000ff; }}
        .plist-bool {{ color: #ff00ff; font-weight: bold; }}
        .plist-null {{ color: #808080; font-style: italic; }}
        .plist-bracket {{ color: #666666; font-weight: bold; }}
        .plist-toggle {{ display: inline-block; width: 12px; cursor: pointer; user-select: none; margin-right: 4px; }}
        .plist-expandable {{ }}
        .plist-collapsed {{ display: none; }}
        .image-viewer {{ text-align: center; padding: 20px; }}
        .image-viewer img {{ max-width: 100%; max-height: 70vh; border-radius: 4px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }}
        .hex-viewer {{ font-family: 'Courier New', monospace; font-size: 12px; background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 4px; white-space: pre; overflow-x: auto; max-height: 70vh; overflow-y: auto; }}
        .hex-offset {{ color: #858585; }}
        .hex-bytes {{ color: #ce9178; }}
        .hex-ascii {{ color: #4ec9b0; }}
        .protobuf-data {{ margin-top: 20px; }}
        .protobuf-data h4 {{ color: #495057; margin-bottom: 15px; font-size: 16px; }}
        .pb-fields {{ background: #e7f3ff; border: 1px solid #2196F3; border-radius: 4px; padding: 15px; max-height: 400px; overflow-y: auto; }}
        .pb-field {{ padding: 6px 0; border-bottom: 1px solid #b3d9ff; }}
        .pb-field:last-child {{ border-bottom: none; }}
        .pb-key {{ font-weight: bold; color: #1976D2; margin-right: 8px; }}
        .pb-value {{ color: #333; font-family: 'Courier New', monospace; font-size: 12px; word-break: break-all; }}
        .footer {{ padding: 20px; text-align: center; color: #6c757d; font-size: 13px; border-top: 1px solid #dee2e6; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>BIOME Stream Analysis Report</h1>
            <div class="meta">
                Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 
                File: {html.escape(self.analyzer.file_path.name)}
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="label">Version</div>
                    <div class="value">{self.analyzer.version}</div>
                </div>
                <div class="summary-item">
                    <div class="label">File Size</div>
                    <div class="value">{self._format_size(self.analyzer.file_size)}</div>
                </div>
                <div class="summary-item">
                    <div class="label">Frames</div>
                    <div class="value">{len(self.analyzer.frames)}</div>
                </div>
                <div class="summary-item">
                    <div class="label">Binary Objects</div>
                    <div class="value">{sum(len(f.binary_objects) for f in self.analyzer.frames)}</div>
                </div>
            </div>
            <div style="margin-top: 20px; font-family: monospace; font-size: 11px; color: #6c757d;">
                SHA256: {self.analyzer.file_hash}
            </div>
        </div>
        
        <div class="frames">
            <h2 style="margin-bottom: 20px; color: #212529;">Frame Details</h2>
            {frames_html}
        </div>
        
        <div class="footer">
            BIOME Stream Analyzer v3.5.1 | Author: Marc Brandt (mb4n6)
        </div>
    </div>
    
    <div id="viewerModal" class="viewer-modal">
        <div class="viewer-content">
            <div class="viewer-header">
                <h3 id="viewerTitle">Viewer</h3>
                <span class="close-btn" onclick="closeViewer()">&times;</span>
            </div>
            <div id="viewerBody"></div>
        </div>
    </div>
    
    <script>
        function closeViewer() {{
            document.getElementById('viewerModal').style.display = 'none';
        }}
        
        function viewPlist(data) {{
            try {{
                document.getElementById('viewerTitle').textContent = 'Plist Viewer - Parsing...';
                document.getElementById('viewerBody').innerHTML = '<div style="padding: 40px; text-align: center;"><div style="font-size: 16px;">Parsing plist data...</div></div>';
                document.getElementById('viewerModal').style.display = 'block';
                
                setTimeout(() => {{
                    try {{
                        const decoded = atob(data);
                        const bytes = new Uint8Array(decoded.length);
                        for(let i = 0; i < decoded.length; i++) {{
                            bytes[i] = decoded.charCodeAt(i);
                        }}
                        
                        let plistObj;
                        let errorMsg = null;
                        let diagnostics = [];
                        
                        // Check for leading zeros and clean data
                        let cleanBytes = bytes;
                        let leadingZeros = 0;
                        while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) {{
                            leadingZeros++;
                        }}
                        
                        if (leadingZeros > 0) {{
                            cleanBytes = bytes.slice(leadingZeros);
                            diagnostics.push('Found ' + leadingZeros + ' leading null bytes (non-standard, possible corruption)');
                        }}
                        
                        // Quick validation
                        if (!cleanBytes || cleanBytes.length < 8) {{
                            errorMsg = 'Data too short to be a valid plist';
                        }} else {{
                            const magic = String.fromCharCode.apply(null, cleanBytes.slice(0, 6));
                            if (!magic.startsWith('bplist')) {{
                                errorMsg = 'Not a binary plist (missing bplist header)';
                                if (leadingZeros > 0) {{
                                    diagnostics.push('Original data had leading zeros at offset 0-' + leadingZeros);
                                }}
                            }} else {{
                                // Check for NSKeyedArchiver
                                const first200 = String.fromCharCode.apply(null, cleanBytes.slice(0, Math.min(200, cleanBytes.length)));
                                if (first200.includes('NSKeyedArchiver') || first200.includes('$archiver')) {{
                                    diagnostics.push('NSKeyedArchiver format detected (serialized Objective-C object)');
                                }}
                                
                                // Try parsing with cleaned data
                                try {{
                                    plistObj = parseBinaryPlist(cleanBytes);
                                }} catch(e) {{
                                    errorMsg = e.message;
                                    diagnostics.push('Parse attempt failed: ' + e.message);
                                }}
                            }}
                        }}
                        
                        if (errorMsg) {{
                            // Show detailed error with diagnostics
                            const hexPreview = Array.from(bytes.slice(0, 128))
                                .map((b, i) => {{
                                    if (i % 16 === 0) return '\\n' + i.toString(16).padStart(8, '0') + ': ' + b.toString(16).padStart(2, '0');
                                    return b.toString(16).padStart(2, '0');
                                }})
                                .join(' ');
                            
                            let diagnosticsHtml = '';
                            if (diagnostics.length > 0) {{
                                diagnosticsHtml = '<div style="margin: 20px 0; padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">' +
                                    '<h4 style="margin: 0 0 10px 0; color: #856404;">Diagnostics:</h4><ul style="margin: 0; padding-left: 20px;">';
                                diagnostics.forEach(d => {{
                                    diagnosticsHtml += '<li style="color: #856404; margin: 5px 0;">' + escapeHtml(d) + '</li>';
                                }});
                                diagnosticsHtml += '</ul></div>';
                            }}
                            
                            document.getElementById('viewerTitle').textContent = 'Plist Viewer - Parse Failed';
                            document.getElementById('viewerBody').innerHTML = 
                                '<div class="plist-tree">' +
                                '<h3 style="color: #dc3545; margin-bottom: 15px;">Failed to parse plist</h3>' +
                                '<p style="margin: 10px 0;"><strong>Error:</strong> ' + escapeHtml(errorMsg) + '</p>' +
                                '<p style="margin: 10px 0;"><strong>Size:</strong> ' + bytes.length + ' bytes</p>' +
                                diagnosticsHtml +
                                '<div style="margin-top: 20px;">' +
                                '<h4 style="color: #495057;">Hex Preview (first 128 bytes):</h4>' +
                                '<pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; font-family: monospace; font-size: 12px;">' + 
                                hexPreview + 
                                '</pre>' +
                                '</div>' +
                                '<div style="margin-top: 20px; padding: 15px; background: #e7f3ff; border-left: 4px solid #2196F3; border-radius: 4px;">' +
                                '<h4 style="margin: 0 0 10px 0; color: #0d47a1;">Possible Causes:</h4>' +
                                '<ul style="margin: 0; padding-left: 20px; color: #1565c0;">' +
                                '<li>File may be corrupted or incomplete</li>' +
                                '<li>Non-standard plist format or padding</li>' +
                                '<li>Extracted from larger binary with offset</li>' +
                                '<li>May require special decoder (e.g., NSKeyedArchiver)</li>' +
                                '</ul>' +
                                '</div>' +
                                '</div>';
                        }} else {{
                            // Successfully parsed - build tree
                            document.getElementById('viewerTitle').textContent = 'Plist Viewer';
                            let infoBox = '';
                            if (diagnostics.length > 0) {{
                                infoBox = '<div style="margin-bottom: 15px; padding: 10px; background: #d4edda; border-left: 4px solid #28a745; border-radius: 4px; font-size: 13px; color: #155724;">' +
                                    '✓ Parsed successfully with corrections applied</div>';
                            }}
                            document.getElementById('viewerBody').innerHTML = 
                                '<div class="plist-tree">' + 
                                infoBox +
                                buildPlistTreeOptimized(plistObj, 0, 0) + 
                                '</div>';
                        }}
                    }} catch(e) {{
                        document.getElementById('viewerTitle').textContent = 'Plist Viewer - Error';
                        document.getElementById('viewerBody').innerHTML = 
                            '<div class="plist-tree" style="color: #dc3545;">' +
                            '<h3>Unexpected Error</h3>' +
                            '<p>' + escapeHtml(e.message) + '</p>' +
                            '<p style="margin-top: 15px; font-size: 13px; color: #6c757d;">Stack trace:</p>' +
                            '<pre style="background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 11px; overflow-x: auto;">' +
                            escapeHtml(e.stack || 'No stack trace available') +
                            '</pre>' +
                            '</div>';
                    }}
                }}, 50);
            }} catch(e) {{
                alert('Failed to view plist: ' + e.message);
                closeViewer();
            }}
        }}
        
        function buildPlistTreeOptimized(obj, level, itemCount) {{
            // Limit depth and items for performance
            if (level > 20) {{
                return '<span class="plist-string" style="color: #999;">[Maximum depth reached]</span>';
            }}
            if (itemCount > 5000) {{
                return '<span class="plist-string" style="color: #999;">[Maximum items reached]</span>';
            }}
            
            if (obj === null) {{
                return '<span class="plist-null">null</span>';
            }}
            if (typeof obj === 'boolean') {{
                return '<span class="plist-bool">' + obj + '</span>';
            }}
            if (typeof obj === 'number') {{
                return '<span class="plist-number">' + obj + '</span>';
            }}
            if (typeof obj === 'string') {{
                // Truncate very long strings
                const str = obj.length > 500 ? obj.substring(0, 500) + '... [truncated]' : obj;
                return '<span class="plist-string">"' + escapeHtml(str) + '"</span>';
            }}
            if (obj instanceof Date) {{
                return '<span class="plist-string">"' + obj.toISOString() + '"</span>';
            }}
            if (obj instanceof Uint8Array || obj instanceof ArrayBuffer) {{
                const bytes = obj instanceof Uint8Array ? obj : new Uint8Array(obj);
                const preview = Array.from(bytes.slice(0, 32))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join(' ');
                return '<span class="plist-string">Data(' + bytes.byteLength + ' bytes): ' + 
                       preview + (bytes.byteLength > 32 ? '...' : '') + '</span>';
            }}
            
            const id = 'n_' + level + '_' + Math.random().toString(36).substr(2, 6);
            
            if (Array.isArray(obj)) {{
                if (obj.length === 0) {{
                    return '<span class="plist-bracket">[]</span>';
                }}
                
                // For large arrays, show first items only
                const maxItems = level > 3 ? 50 : 100;
                const displayItems = obj.slice(0, maxItems);
                const truncated = obj.length > maxItems;
                
                let html = '<div class="plist-expandable">';
                html += '<span class="plist-toggle" onclick="toggleNode(\\'' + id + '\\')">▼</span>';
                html += '<span class="plist-bracket">[</span> <span style="color: #999;">(' + obj.length + ' items)</span>';
                html += '<div id="' + id + '" class="plist-node">';
                
                displayItems.forEach((item, idx) => {{
                    html += '<div><span class="plist-key">' + idx + ':</span> ' + 
                           buildPlistTreeOptimized(item, level + 1, itemCount + 1) + '</div>';
                }});
                
                if (truncated) {{
                    html += '<div style="color: #999; font-style: italic;">... ' + 
                           (obj.length - maxItems) + ' more items (truncated for performance)</div>';
                }}
                
                html += '</div>';
                html += '<span class="plist-bracket">]</span>';
                html += '</div>';
                return html;
            }}
            
            if (typeof obj === 'object') {{
                const keys = Object.keys(obj);
                if (keys.length === 0) {{
                    return '<span class="plist-bracket">{{}}</span>';
                }}
                
                // For large dicts, show first keys only
                const maxKeys = level > 3 ? 50 : 100;
                const displayKeys = keys.slice(0, maxKeys);
                const truncated = keys.length > maxKeys;
                
                let html = '<div class="plist-expandable">';
                html += '<span class="plist-toggle" onclick="toggleNode(\\'' + id + '\\')">▼</span>';
                html += '<span class="plist-bracket">{{</span> <span style="color: #999;">(' + keys.length + ' keys)</span>';
                html += '<div id="' + id + '" class="plist-node">';
                
                displayKeys.forEach(key => {{
                    html += '<div><span class="plist-key">' + escapeHtml(key) + ':</span> ' + 
                           buildPlistTreeOptimized(obj[key], level + 1, itemCount + 1) + '</div>';
                }});
                
                if (truncated) {{
                    html += '<div style="color: #999; font-style: italic;">... ' + 
                           (keys.length - maxKeys) + ' more keys (truncated for performance)</div>';
                }}
                
                html += '</div>';
                html += '<span class="plist-bracket">}}</span>';
                html += '</div>';
                return html;
            }}
            
            return '<span>' + escapeHtml(String(obj)) + '</span>';
        }}
        
        function toggleNode(id) {{
            const node = document.getElementById(id);
            const toggle = node.previousElementSibling;
            if (node.classList.contains('plist-collapsed')) {{
                node.classList.remove('plist-collapsed');
                toggle.textContent = '▼';
            }} else {{
                node.classList.add('plist-collapsed');
                toggle.textContent = '▶';
            }}
        }}
        
        function parseBinaryPlist(bytes) {{
            // Enhanced binary plist parser (bplist00 format) with validation
            if (!bytes || bytes.length < 40) {{
                throw new Error('File too small (minimum 40 bytes required)');
            }}
            
            const magic = String.fromCharCode.apply(null, bytes.slice(0, 8));
            if (!magic.startsWith('bplist')) {{
                throw new Error('Invalid magic header: ' + magic.substring(0, 6));
            }}
            
            // Read trailer (last 32 bytes)
            const trailerStart = bytes.length - 32;
            if (trailerStart < 8) {{
                throw new Error('File too small for trailer');
            }}
            
            const view = new DataView(bytes.buffer, bytes.byteOffset);
            
            try {{
                const offsetSize = bytes[trailerStart + 6];
                const objectRefSize = bytes[trailerStart + 7];
                
                if (offsetSize < 1 || offsetSize > 8) {{
                    throw new Error('Invalid offset size: ' + offsetSize);
                }}
                if (objectRefSize < 1 || objectRefSize > 8) {{
                    throw new Error('Invalid object ref size: ' + objectRefSize);
                }}
                
                const numObjects = Number(view.getBigUint64(trailerStart + 8));
                const topObject = Number(view.getBigUint64(trailerStart + 16));
                const offsetTableOffset = Number(view.getBigUint64(trailerStart + 24));
                
                if (numObjects > 1000000) {{
                    throw new Error('Too many objects: ' + numObjects);
                }}
                if (topObject >= numObjects) {{
                    throw new Error('Invalid top object index: ' + topObject + ' >= ' + numObjects);
                }}
                if (offsetTableOffset >= bytes.length) {{
                    throw new Error('Invalid offset table position');
                }}
                
                // Read offset table
                const offsets = [];
                for (let i = 0; i < numObjects; i++) {{
                    let offset = 0;
                    const pos = offsetTableOffset + i * offsetSize;
                    if (pos + offsetSize > bytes.length) {{
                        throw new Error('Offset table extends beyond file');
                    }}
                    for (let j = 0; j < offsetSize; j++) {{
                        offset = (offset << 8) | bytes[pos + j];
                    }}
                    if (offset >= bytes.length) {{
                        throw new Error('Invalid offset: ' + offset);
                    }}
                    offsets.push(offset);
                }}
                
                const maxDepth = 100;
                const parsedObjects = new Map();
                
                // Parse objects with recursion limit
                function parseObject(index, depth = 0) {{
                    if (depth > maxDepth) {{
                        throw new Error('Maximum recursion depth exceeded');
                    }}
                    if (index < 0 || index >= numObjects) {{
                        throw new Error('Object index out of range: ' + index);
                    }}
                    
                    // Check cache
                    if (parsedObjects.has(index)) {{
                        return parsedObjects.get(index);
                    }}
                    
                    const offset = offsets[index];
                    if (offset >= bytes.length) {{
                        throw new Error('Invalid offset for object ' + index);
                    }}
                    
                    const marker = bytes[offset];
                    const type = (marker & 0xF0) >> 4;
                    const info = marker & 0x0F;
                    let result;
                    
                    try {{
                        if (type === 0) {{ // null, bool, fill
                            if (info === 0) result = null;
                            else if (info === 8) result = false;
                            else if (info === 9) result = true;
                            else result = null;
                        }}
                        else if (type === 1) {{ // int
                            const size = 1 << info;
                            if (offset + 1 + size > bytes.length) throw new Error('Int extends beyond file');
                            let value = 0;
                            for (let i = 0; i < size; i++) {{
                                value = (value * 256) + bytes[offset + 1 + i];
                            }}
                            result = value;
                        }}
                        else if (type === 2) {{ // real
                            const size = 1 << info;
                            if (offset + 1 + size > bytes.length) throw new Error('Real extends beyond file');
                            if (size === 4) {{
                                result = view.getFloat32(offset + 1);
                            }} else if (size === 8) {{
                                result = view.getFloat64(offset + 1);
                            }} else {{
                                result = 0;
                            }}
                        }}
                        else if (type === 3) {{ // date
                            if (offset + 9 > bytes.length) throw new Error('Date extends beyond file');
                            const timestamp = view.getFloat64(offset + 1);
                            result = new Date((timestamp + 978307200) * 1000);
                        }}
                        else if (type === 4) {{ // data
                            let length = info;
                            let dataOffset = offset + 1;
                            if (info === 0x0F) {{
                                if (dataOffset >= bytes.length) throw new Error('Data length marker missing');
                                const intMarker = bytes[dataOffset];
                                const intSize = 1 << (intMarker & 0x0F);
                                length = 0;
                                for (let i = 0; i < intSize; i++) {{
                                    length = (length << 8) | bytes[dataOffset + 1 + i];
                                }}
                                dataOffset += 1 + intSize;
                            }}
                            if (dataOffset + length > bytes.length) throw new Error('Data extends beyond file');
                            result = bytes.slice(dataOffset, dataOffset + length);
                        }}
                        else if (type === 5) {{ // ascii string
                            let length = info;
                            let strOffset = offset + 1;
                            if (info === 0x0F) {{
                                if (strOffset >= bytes.length) throw new Error('String length marker missing');
                                const intMarker = bytes[strOffset];
                                const intSize = 1 << (intMarker & 0x0F);
                                length = 0;
                                for (let i = 0; i < intSize; i++) {{
                                    length = (length << 8) | bytes[strOffset + 1 + i];
                                }}
                                strOffset += 1 + intSize;
                            }}
                            if (strOffset + length > bytes.length) throw new Error('String extends beyond file');
                            result = String.fromCharCode.apply(null, bytes.slice(strOffset, strOffset + length));
                        }}
                        else if (type === 6) {{ // unicode string
                            let length = info;
                            let strOffset = offset + 1;
                            if (info === 0x0F) {{
                                if (strOffset >= bytes.length) throw new Error('Unicode string length marker missing');
                                const intMarker = bytes[strOffset];
                                const intSize = 1 << (intMarker & 0x0F);
                                length = 0;
                                for (let i = 0; i < intSize; i++) {{
                                    length = (length << 8) | bytes[strOffset + 1 + i];
                                }}
                                strOffset += 1 + intSize;
                            }}
                            if (strOffset + length * 2 > bytes.length) throw new Error('Unicode string extends beyond file');
                            const chars = [];
                            for (let i = 0; i < length; i++) {{
                                chars.push(view.getUint16(strOffset + i * 2));
                            }}
                            result = String.fromCharCode.apply(null, chars);
                        }}
                        else if (type === 10) {{ // array
                            let length = info;
                            let arrOffset = offset + 1;
                            if (info === 0x0F) {{
                                if (arrOffset >= bytes.length) throw new Error('Array length marker missing');
                                const intMarker = bytes[arrOffset];
                                const intSize = 1 << (intMarker & 0x0F);
                                length = 0;
                                for (let i = 0; i < intSize; i++) {{
                                    length = (length << 8) | bytes[arrOffset + 1 + i];
                                }}
                                arrOffset += 1 + intSize;
                            }}
                            if (arrOffset + length * objectRefSize > bytes.length) throw new Error('Array refs extend beyond file');
                            const array = [];
                            for (let i = 0; i < length; i++) {{
                                let ref = 0;
                                for (let j = 0; j < objectRefSize; j++) {{
                                    ref = (ref << 8) | bytes[arrOffset + i * objectRefSize + j];
                                }}
                                array.push(parseObject(ref, depth + 1));
                            }}
                            result = array;
                        }}
                        else if (type === 13) {{ // dict
                            let length = info;
                            let dictOffset = offset + 1;
                            if (info === 0x0F) {{
                                if (dictOffset >= bytes.length) throw new Error('Dict length marker missing');
                                const intMarker = bytes[dictOffset];
                                const intSize = 1 << (intMarker & 0x0F);
                                length = 0;
                                for (let i = 0; i < intSize; i++) {{
                                    length = (length << 8) | bytes[dictOffset + 1 + i];
                                }}
                                dictOffset += 1 + intSize;
                            }}
                            if (dictOffset + length * 2 * objectRefSize > bytes.length) throw new Error('Dict refs extend beyond file');
                            const dict = {{}};
                            for (let i = 0; i < length; i++) {{
                                let keyRef = 0;
                                for (let j = 0; j < objectRefSize; j++) {{
                                    keyRef = (keyRef << 8) | bytes[dictOffset + i * objectRefSize + j];
                                }}
                                let valRef = 0;
                                for (let j = 0; j < objectRefSize; j++) {{
                                    valRef = (valRef << 8) | bytes[dictOffset + (length + i) * objectRefSize + j];
                                }}
                                const key = parseObject(keyRef, depth + 1);
                                dict[key] = parseObject(valRef, depth + 1);
                            }}
                            result = dict;
                        }}
                        else {{
                            throw new Error('Unsupported type: ' + type);
                        }}
                    }} catch (e) {{
                        throw new Error('Error parsing object ' + index + ': ' + e.message);
                    }}
                    
                    parsedObjects.set(index, result);
                    return result;
                }}
                
                return parseObject(topObject);
                
            }} catch(e) {{
                throw new Error('Parse error: ' + e.message);
            }}
        }}
        
        function viewImage(data, type) {{
            const imgType = type.toLowerCase().replace('gif87a', 'gif').replace('gif89a', 'gif');
            document.getElementById('viewerTitle').textContent = 'Image Viewer - ' + type;
            document.getElementById('viewerBody').innerHTML = '<div class="image-viewer"><img src="data:image/' + imgType + ';base64,' + data + '" /></div>';
            document.getElementById('viewerModal').style.display = 'block';
        }}
        
        function viewHex(data, type) {{
            try {{
                const bytes = atob(data);
                let hexHtml = '';
                for(let i = 0; i < Math.min(bytes.length, 8192); i += 16) {{
                    const offset = i.toString(16).padStart(8, '0');
                    let hexPart = '';
                    let asciiPart = '';
                    for(let j = 0; j < 16 && i + j < bytes.length; j++) {{
                        const byte = bytes.charCodeAt(i + j);
                        hexPart += byte.toString(16).padStart(2, '0') + ' ';
                        asciiPart += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
                    }}
                    hexHtml += '<span class="hex-offset">' + offset + '</span>  <span class="hex-bytes">' + hexPart.padEnd(48, ' ') + '</span>  <span class="hex-ascii">' + asciiPart + '</span>\\n';
                }}
                if(bytes.length > 8192) {{
                    hexHtml += '\\n... (' + (bytes.length - 8192) + ' more bytes)';
                }}
                document.getElementById('viewerTitle').textContent = 'Hex Viewer - ' + type;
                document.getElementById('viewerBody').innerHTML = '<div class="hex-viewer">' + hexHtml + '</div>';
                document.getElementById('viewerModal').style.display = 'block';
            }} catch(e) {{
                alert('Error viewing hex: ' + e.message);
            }}
        }}
        
        function downloadBlob(data, filename) {{
            try {{
                const byteCharacters = atob(data);
                const byteNumbers = new Array(byteCharacters.length);
                for (let i = 0; i < byteCharacters.length; i++) {{
                    byteNumbers[i] = byteCharacters.charCodeAt(i);
                }}
                const byteArray = new Uint8Array(byteNumbers);
                const blob = new Blob([byteArray], {{ type: 'application/octet-stream' }});
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            }} catch(e) {{
                alert('Error downloading: ' + e.message);
            }}
        }}
        
        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}
        
        window.onclick = function(event) {{
            const modal = document.getElementById('viewerModal');
            if (event.target == modal) {{
                closeViewer();
            }}
        }}
    </script>
</body>
</html>'''
    
    def _frame_html(self, frame, frame_idx):
        info_items = [
            ('Offset', f'0x{frame.offset:08X}' if frame.offset else 'N/A'),
            ('Size', f'{frame.get_frame_size():,} bytes'),
            ('Timestamp', frame.get_timestamp_str()),
        ]
        
        if frame.crc is not None:
            crc_status = '✓' if frame.crc_ok else '✗'
            info_items.append(('CRC', f'{frame.crc:08X} {crc_status}'))
        
        info_html = "\n".join(
            f'<div class="info-item"><span class="info-label">{label}:</span><span class="info-value">{value}</span></div>'
            for label, value in info_items
        )
        
        binary_html = ""
        if frame.binary_objects:
            objs_html = "\n".join(self._binary_object_html(obj, frame_idx, obj_idx, frame) 
                                 for obj_idx, obj in enumerate(frame.binary_objects))
            binary_html = f'''
            <div class="binary-objects">
                <h4>Binary Objects ({len(frame.binary_objects)})</h4>
                {objs_html}
            </div>'''
        
        protobuf_html = ""
        if frame.protobuf_data:
            pb_items = []
            for key, value in frame.protobuf_data.items():
                value_str = str(value)
                if len(value_str) > 200:
                    value_str = value_str[:200] + '...'
                pb_items.append(f'<div class="pb-field"><span class="pb-key">{html.escape(key)}:</span> <span class="pb-value">{html.escape(value_str)}</span></div>')
            
            protobuf_html = f'''
            <div class="protobuf-data">
                <h4>Protobuf Fields ({len(frame.protobuf_data)})</h4>
                <div class="pb-fields">
                    {"".join(pb_items)}
                </div>
            </div>'''
        
        return f'''
        <div class="frame">
            <div class="frame-header">
                <h3>Frame {frame.index}</h3>
                <span class="frame-info">v{frame.version}</span>
            </div>
            <div class="frame-body">
                <div class="info-grid">
                    {info_html}
                </div>
                {binary_html}
                {protobuf_html}
            </div>
        </div>'''
    
    def _binary_object_html(self, obj, frame_idx, obj_idx, frame):
        obj_type = obj.get('type', 'Unknown')
        size = obj.get('size', 0)
        entropy = obj.get('entropy', 0)
        offset = obj.get('offset', 0)
        
        data_b64 = ""
        if frame.payload and offset + size <= len(frame.payload):
            data_b64 = base64.b64encode(frame.payload[offset:offset+size]).decode('ascii')
        
        buttons = []
        filename = f"frame{frame_idx}_obj{obj_idx}.{self._get_file_extension(obj_type)}"
        
        if obj_type in ['JPEG', 'PNG', 'GIF87a', 'GIF89a', 'Bitmap', 'ICO']:
            buttons.append(f'<button class="btn-view" onclick="viewImage(\'{data_b64}\', \'{obj_type}\')">🖼️ View Image</button>')
        
        if obj_type == 'Binary PLIST':
            buttons.append(f'<button class="btn-view" onclick="viewPlist(\'{data_b64}\')">📋 View Plist</button>')
        
        buttons.append(f'<button class="btn-hex" onclick="viewHex(\'{data_b64}\', \'{obj_type}\')">🔍 Hex View</button>')
        buttons.append(f'<button class="btn-download" onclick="downloadBlob(\'{data_b64}\', \'{filename}\')">💾 Download</button>')
        
        return f'''
        <div class="binary-object">
            <div class="type">
                <span>{html.escape(obj_type)}</span>
                <span>({size:,} bytes, Entropy: {entropy:.2f}, Offset: 0x{offset:X})</span>
            </div>
            <div class="controls">
                {"".join(buttons)}
            </div>
            <div class="hex-preview">{html.escape(obj.get('hex_preview', ''))[:96]}</div>
        </div>'''
    
    def _format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f'{size:.1f} {unit}'
            size /= 1024
        return f'{size:.1f} TB'
