#!/usr/bin/env python
import http.server
import socketserver
import os

PORT = 8000
DIRECTORY = "dashboard"

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        super().end_headers()
    
    def guess_type(self, path):
        if path == '/':
            return 'text/html'
        return super().guess_type(path)

os.chdir(os.path.dirname(os.path.abspath(__file__)))

with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
    print(f"Serving dashboard at http://localhost:{PORT}")
    httpd.serve_forever()