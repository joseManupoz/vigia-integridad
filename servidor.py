import os
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(os.environ.get("PORT", 8080))

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"VIGIA funcionando OK")
    def log_message(self, *a): pass

print(f"[VIGIA] Iniciando en puerto {PORT}", flush=True)
server = HTTPServer(("0.0.0.0", PORT), Handler)
print("[VIGIA] Servidor listo", flush=True)
server.serve_forever()
