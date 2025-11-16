#!/usr/bin/env python3
"""Simple HTTP server for testing DDoS detection."""

import http.server
import socketserver
import threading

class TestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>Test Server - DDoS Target</h1>')
    
    def do_POST(self):
        self.do_GET()

def start_server(port=9999):
    with socketserver.TCPServer(("", port), TestHandler) as httpd:
        print(f"🚀 Test server running on http://192.168.8.100:{port}")
        print("Press Ctrl+C to stop")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Server stopped")

if __name__ == "__main__":
    start_server()