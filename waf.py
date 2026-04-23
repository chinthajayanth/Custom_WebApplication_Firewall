from flask import Flask, request, abort
import re
import json
from urllib.parse import unquote
import requests

app = Flask(__name__)

# =========================================================
# 1. FIREWALL CONFIGURATION & THREAT SIGNATURES
# =========================================================
ALLOWED_HOSTS = ['localhost:8080', '127.0.0.1:8080']
MAX_CONTENT_LENGTH = 1024 * 1024  # 1 MB
ALLOWED_CONTENT_TYPES = ['application/json', 'application/x-www-form-urlencoded']
BLOCKED_USER_AGENTS = re.compile(r'(?i)(MSIE [1-8]\.|sqlmap|nmap|nikto|dirb)')

# The Blacklist (Regex)
WAF_RULES = {
    'SQL_INJECTION': re.compile(r'(?i)(UNION.*SELECT|INSERT.*INTO|UPDATE.*SET|DELETE.*FROM|DROP.*TABLE|--|1=1)'),
    'CROSS_SITE_SCRIPTING': re.compile(r'(?i)(<script>|javascript:|onerror=|onload=|alert\()'),
    'DIRECTORY_TRAVERSAL': re.compile(r'(?i)(\.\./|\.\.\\|/etc/passwd|boot\.ini)'),
    'COMMAND_INJECTION': re.compile(r'(?i)(;|\||&&|`)\s*(ls|whoami|cat|cmd|net\s+user|ping)')
}

def scan_payload(data_list):
    """Deep Packet Inspection: Scans decoded data against threat signatures."""
    for item in data_list:
        if not item: continue
        item_str = str(item)
        for attack_type, rule in WAF_RULES.items():
            if rule.search(item_str):
                print(f"\n[🚨 WAF BLOCK] {attack_type} detected!")
                print(f"Payload Snippet: {item_str[:50]}...\n")
                abort(403)

# =========================================================
# 2. THE WAF ENGINE (Middleware)
# =========================================================
@app.before_request
def waf_engine():
    method = request.method
    print(f"\n[WAF] Inspecting {method} request...")

    # --- PHASE 1: HTTP SMUGGLING & STRUCTURAL DEFENSE ---
    if 'Content-Length' in request.headers and 'Transfer-Encoding' in request.headers:
        print("[🚨 WAF BLOCK] Smuggling Attempt (CL/TE Desync)!")
        abort(400)

    # --- PHASE 2: HEADER VALIDATION (Fast Checks) ---
    if request.headers.get('Host', '') not in ALLOWED_HOSTS: abort(403)
    
    user_agent = request.headers.get('User-Agent', '')
    if BLOCKED_USER_AGENTS.search(user_agent) or not user_agent: abort(403)
    
    if request.content_length and request.content_length > MAX_CONTENT_LENGTH: abort(413)

    # --- PHASE 3: DEEP PACKET INSPECTION (The Body & URL) ---
    # 1. Scan the URL (Decoded)
    scan_payload([unquote(request.url)])

    # 2. Inspect the Body (If data is present)
    if method in ['POST', 'PUT', 'PATCH'] and (request.data or request.form):
        content_type = request.headers.get('Content-Type', '').split(';')[0]
        
        if content_type not in ALLOWED_CONTENT_TYPES: 
            print(f"[🚨 WAF BLOCK] Illegal Content-Type: {content_type}")
            abort(415)

        # STRICT PARSING: If it claims to be JSON, prove it.
        if content_type == 'application/json':
            try:
                # If this fails, the data is malformed (potential attack)
                json.loads(request.data)
            except json.JSONDecodeError:
                print("[🚨 WAF BLOCK] Malformed JSON Body!")
                abort(400)

        # THE GOLDEN RULE: Decode the body, then scan it.
        data_to_scan = list(request.form.values())
        if request.data:
            decoded_body = unquote(request.data.decode('utf-8', errors='ignore'))
            data_to_scan.append(decoded_body)
            
        scan_payload(data_to_scan)

# =========================================================
# 3. THE REVERSE PROXY (Forwarding Safe Traffic)
# =========================================================
# Let's say your vulnerable app (DVWA) is running on port 5000
BACKEND_SERVER_URL = "http://localhost:5000"

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def reverse_proxy(path):
    print("[WAF] Request is clean. Forwarding to backend server...")
    
    # 1. Build the exact URL for the backend server
    target_url = f"{BACKEND_SERVER_URL}/{path}"
    
    # 2. Forward the exact request the user sent
    # We pass along the method, the headers, the form data, and the raw body
    backend_response = requests.request(
        method=request.method,
        url=target_url,
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=request.get_data(),
        params=request.args,
        allow_redirects=False
    )
    
    # 3. Take the backend server's response and send it back to the user
    return backend_response.content, backend_response.status_code, backend_response.headers.items()

if __name__ == '__main__':
    print("🛡️ Ultimate WAF Proxy Online on port 8080 🛡️\n")
    app.run(host='0.0.0.0', port=8080, debug=True)