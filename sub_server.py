import base64
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = 8000
SECRET_PATH = "/sub"

CONFIG = {
    "domain": "app-analytics-services.com",
    "port": 443,
    "uuid": "cxlvin777",
    "password": "Cxlvin777",
    "ss_method": "chacha20-ietf-poly1305"
}

def generate_subscription(host_header):
    # Fallback to default domain if Host header is missing
    domain = host_header.split(':')[0] if host_header else CONFIG["domain"]
    port = CONFIG["port"]
    uuid = CONFIG["uuid"]
    pwd = CONFIG["password"]
    ss_credentials = base64.b64encode(f"{CONFIG['ss_method']}:{pwd}".encode()).decode()

    # VMess JSON user objects
    vmess_base = {
        "v": "2",
        "add": domain,
        "port": str(port),
        "id": uuid,
        "aid": "0",
        "scy": "auto",
        "tls": "tls",
        "sni": domain,
        "alpn": "h2,http/1.1",
        "fp": "chrome"
    }

    links = []

    # ==========================================
    # 1. gRPC NODES
    # ==========================================
    # VLESS
    links.append(
        f"vless://{uuid}@{domain}:{port}?mode=gun&security=tls&alpn=h2%2Chttp%2F1.1&encryption=none&insecure=0&fp=chrome&type=grpc&serviceName=cxlvinvl-grpc&allowInsecure=0&sni={domain}#vless-grpc"
    )
    # TROJAN
    links.append(
        f"trojan://{pwd}@{domain}:{port}?mode=gun&security=tls&alpn=h2%2Chttp%2F1.1&insecure=0&fp=chrome&type=grpc&serviceName=cxlvintr-grpc&allowInsecure=0&sni={domain}#trojan-grpc"
    )
    # VMESS
    vmess_grpc = vmess_base.copy()
    vmess_grpc.update({
        "ps": "vmess-grpc",
        "net": "grpc",
        "type": "gun",
        "path": "cxlvinvm-grpc"
    })
    links.append("vmess://" + base64.b64encode(json.dumps(vmess_grpc).encode()).decode())
    # SHADOWSOCKS
    links.append(
        f"ss://{ss_credentials}@{domain}:{port}?mode=gun&security=tls&alpn=h2%2Chttp%2F1.1&insecure=0&fp=chrome&type=grpc&serviceName=cxlvinss-grpc&allowInsecure=0&sni={domain}#ss-grpc"
    )

    # ==========================================
    # 2. WEBSOCKET NODES
    # ==========================================
    # VLESS
    links.append(
        f"vless://{uuid}@{domain}:{port}?encryption=none&type=ws&headerType=none&path=%2FCxlvinVlWS%3Fed%3D2560&security=tls#CxlvinVlWS%20v6"
    )
    # TROJAN
    links.append(
        f"trojan://{pwd}@{domain}:{port}?type=ws&headerType=none&path=%2FCxlvinTRWS%3Fed%3D2560&security=tls#CxlvinTRWS%20v6"
    )
    # VMESS
    vmess_ws = vmess_base.copy()
    vmess_ws.update({
        "ps": "CxlvinVMWS v6",
        "net": "ws",
        "type": "none",
        "host": domain,
        "path": "/CxlvinVMWS?ed=2560"
    })
    links.append("vmess://" + base64.b64encode(json.dumps(vmess_ws).encode()).decode())
    # SHADOWSOCKS
    links.append(
        f"ss://{ss_credentials}@{domain}:{port}?type=ws&headerType=none&path=%2FCxlvinSSWS%3Fed%3D2560&security=tls#CxlvinSSWS%20v6"
    )

    # ==========================================
    # 3. HTTP UPGRADE NODES
    # ==========================================
    # VLESS
    links.append(
        f"vless://{uuid}@{domain}:{port}?encryption=none&type=httpupgrade&headerType=none&path=%2FCxlvinVlHU%3Fed%3D2560&security=tls#CxlvinVlHU%20v6"
    )
    # TROJAN
    links.append(
        f"trojan://{pwd}@{domain}:{port}?type=httpupgrade&headerType=none&path=%2FCxlvinTRHU%3Fed%3D2560&security=tls#CxlvinTRHU%20v6"
    )
    # VMESS
    vmess_hu = vmess_base.copy()
    vmess_hu.update({
        "ps": "CxlvinVMHU v6",
        "net": "httpupgrade",
        "type": "none",
        "host": domain,
        "path": "/CxlvinVMHU?ed=2560"
    })
    links.append("vmess://" + base64.b64encode(json.dumps(vmess_hu).encode()).decode())
    # SHADOWSOCKS
    links.append(
        f"ss://{ss_credentials}@{domain}:{port}?type=httpupgrade&headerType=none&path=%2FCxlvinSSHU%3Fed%3D2560&security=tls#CxlvinSSHU%20v6"
    )

    # ==========================================
    # 4. XHTTP NODES
    # ==========================================
    # VLESS
    links.append(
        f"vless://{uuid}@{domain}:{port}?encryption=none&type=xhttp&headerType=auto&path=%2FCxlvinVlXH%3Fed%3D2560&security=tls#CxlvinVlXH%20v6"
    )
    # TROJAN
    links.append(
        f"trojan://{pwd}@{domain}:{port}?type=xhttp&headerType=auto&path=%2FCxlvinTRXH%3Fed%3D2560&security=tls#CxlvinTRXH%20v6"
    )
    # VMESS
    vmess_xh = vmess_base.copy()
    vmess_xh.update({
        "ps": "CxlvinVMXH v6",
        "net": "xhttp",
        "type": "auto",
        "host": domain,
        "path": "/CxlvinVMXH?ed=2560"
    })
    links.append("vmess://" + base64.b64encode(json.dumps(vmess_xh).encode()).decode())
    # SHADOWSOCKS
    links.append(
        f"ss://{ss_credentials}@{domain}:{port}?type=xhttp&headerType=auto&path=%2FCxlvinSSXH%3Fed%3D2560&security=tls#CxlvinSSXH%20v6"
    )

    raw_payload = "\n".join(links)
    return base64.b64encode(raw_payload.encode('utf-8'))


class SubHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == SECRET_PATH or self.path.startswith(f"{SECRET_PATH}?"):
            host_header = self.headers.get('Host', '')
            sub_body = generate_subscription(host_header)
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Profile-Update-Interval', '24')
            self.end_headers()
            self.wfile.write(sub_body)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def log_message(self, format, *args):
        return

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', PORT), SubHandler)
    print(f"Subscription server running on port {PORT}...")
    server.serve_forever()
