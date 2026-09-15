import base64
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = 8000
SECRET_PATH = "/sub"

CONFIG = {
    "default_domain": "app-analytics-services.com",
    "port": 443,
    "uuid": "cxlvin777",
    "password": "Cxlvin777",
    "ss_method": "chacha20-ietf-poly1305"
}

def extract_run_app_host(host_header):
    """Extracts host without port from HTTP Host header for authority."""
    if host_header:
        return host_header.split(':')[0]
    return "example.run.app"

def generate_subscription(host_header):
    run_app_host = extract_run_app_host(host_header)
    fixed_address = "app-analytics-services.com"
    port = CONFIG["port"]
    uuid = CONFIG["uuid"]
    pwd = CONFIG["password"]
    ss_credentials = base64.b64encode(f"{CONFIG['ss_method']}:{pwd}".encode()).decode()

    vmess_base = {
        "v": "2",
        "add": fixed_address,
        "port": str(port),
        "id": uuid,
        "aid": "0",
        "scy": "auto",
        "tls": "tls",
        "sni": fixed_address,
        "alpn": "h2,http/1.1",
        "fp": "chrome"
    }

    links = []

    # 1. gRPC NODES
    links.append(
        f"vless://{uuid}@{fixed_address}:{port}?mode=gun&security=tls&alpn=h2%2Chttp%2F1.1&encryption=none&insecure=0&fp=chrome&type=grpc&serviceName=cxlvinvl-grpc&authority={run_app_host}&allowInsecure=0&sni={fixed_address}#vless-grpc"
    )
    links.append(
        f"trojan://{pwd}@{fixed_address}:{port}?mode=gun&security=tls&alpn=h2%2Chttp%2F1.1&insecure=0&fp=chrome&type=grpc&serviceName=cxlvintr-grpc&authority={run_app_host}&allowInsecure=0&sni={fixed_address}#trojan-grpc"
    )
    vmess_grpc = vmess_base.copy()
    vmess_grpc.update({
        "ps": "vmess-grpc",
        "net": "grpc",
        "type": "gun",
        "path": "cxlvinvm-grpc",
        "host": run_app_host
    })
    links.append("vmess://" + base64.b64encode(json.dumps(vmess_grpc).encode()).decode())
    links.append(
        f"ss://{ss_credentials}@{fixed_address}:{port}?mode=gun&security=tls&alpn=h2%2Chttp%2F1.1&insecure=0&fp=chrome&type=grpc&serviceName=cxlvinss-grpc&authority={run_app_host}&allowInsecure=0&sni={fixed_address}#ss-grpc"
    )

    # 2. WEBSOCKET NODES
    links.append(
        f"vless://{uuid}@{fixed_address}:{port}?encryption=none&type=ws&headerType=none&path=%2FCxlvinVlWS%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinVlWS%20v6"
    )
    links.append(
        f"trojan://{pwd}@{fixed_address}:{port}?type=ws&headerType=none&path=%2FCxlvinTRWS%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinTRWS%20v6"
    )
    vmess_ws = vmess_base.copy()
    vmess_ws.update({"ps": "CxlvinVMWS v6", "net": "ws", "type": "none", "host": run_app_host, "path": "/CxlvinVMWS?ed=2560"})
    links.append("vmess://" + base64.b64encode(json.dumps(vmess_ws).encode()).decode())
    links.append(
        f"ss://{ss_credentials}@{fixed_address}:{port}?type=ws&headerType=none&path=%2FCxlvinSSWS%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinSSWS%20v6"
    )

    # 3. HTTP UPGRADE NODES
    links.append(
        f"vless://{uuid}@{fixed_address}:{port}?encryption=none&type=httpupgrade&headerType=none&path=%2FCxlvinVlHU%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinVlHU%20v6"
    )
    links.append(
        f"trojan://{pwd}@{fixed_address}:{port}?type=httpupgrade&headerType=none&path=%2FCxlvinTRHU%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinTRHU%20v6"
    )
    vmess_hu = vmess_base.copy()
    vmess_hu.update({"ps": "CxlvinVMHU v6", "net": "httpupgrade", "type": "none", "host": run_app_host, "path": "/CxlvinVMHU?ed=2560"})
    links.append("vmess://" + base64.b64encode(json.dumps(vmess_hu).encode()).decode())
    links.append(
        f"ss://{ss_credentials}@{fixed_address}:{port}?type=httpupgrade&headerType=none&path=%2FCxlvinSSHU%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinSSHU%20v6"
    )

    # 4. XHTTP NODES
    links.append(
        f"vless://{uuid}@{fixed_address}:{port}?encryption=none&type=xhttp&headerType=auto&path=%2FCxlvinVlXH%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinVlXH%20v6"
    )
    links.append(
        f"trojan://{pwd}@{fixed_address}:{port}?type=xhttp&headerType=auto&path=%2FCxlvinTRXH%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinTRXH%20v6"
    )
    vmess_xh = vmess_base.copy()
    vmess_xh.update({"ps": "CxlvinVMXH v6", "net": "xhttp", "type": "auto", "host": run_app_host, "path": "/CxlvinVMXH?ed=2560"})
    links.append("vmess://" + base64.b64encode(json.dumps(vmess_xh).encode()).decode())
    links.append(
        f"ss://{ss_credentials}@{fixed_address}:{port}?type=xhttp&headerType=auto&path=%2FCxlvinSSXH%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinSSXH%20v6"
    )

    raw_payload = "\n".join(links)
    return base64.b64encode(raw_payload.encode('utf-8'))

def generate_raw_client_config(host_header):
    """Generates valid Xray JSON config dynamically injecting authority from .run.app request."""
    run_app_host = extract_run_app_host(host_header)

    raw_config = {
        "dns": {
            "hosts": {
                "domain:googleapis.cn": "googleapis.com",
                "dns.alidns.com": [
                    "223.5.5.5",
                    "223.6.6.6",
                    "2400:3200::1",
                    "2400:3200:baba::1"
                ],
                "one.one.one.one": [
                    "1.1.1.1",
                    "1.0.0.1",
                    "2606:4700:4700::1111",
                    "2606:4700:4700::1001"
                ],
                "static-00.iconduck.com": [
                    "9.9.9.11",
                    "149.112.112.11",
                    "2620:fe::fe",
                    "2620:fe::11"
                ],
                "dot.pub": [
                    "1.12.12.12",
                    "120.53.53.53"
                ],
                "images.icon-icons.com": [
                    "208.67.222.222",
                    "208.67.220.220",
                    "2620:119:35::35"
                ],
                "dns.google": [
                    "8.8.8.8",
                    "8.8.4.4",
                    "2001:4860:4860::8888",
                    "2001:4860:4860::8844"
                ],
                "blog.uncensoreddns.org": [
                    "91.239.100.100",
                    "89.233.43.71",
                    "2001:67c:28a4::"
                ],
                "dns.quad9.net": [
                    "9.9.9.9",
                    "149.112.112.112",
                    "2620:fe::fe",
                    "2620:fe::9"
                ],
                "common.dot.dns.yandex.net": [
                    "77.88.8.8",
                    "77.88.8.1",
                    "2a02:6b8::feed:0ff",
                    "2a02:6b8:0:1::feed:0ff"
                ]
            },
            "disableCache": False,
            "servers": [
                "1.1.1.1",
                "223.5.5.5",
                "8.8.8.8"
            ]
        },
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "listen": "0.0.0.0",
                "port": 1080,
                "protocol": "dokodemo-door",
                "settings": {
                    "network": "tcp,udp",
                    "followRedirect": True
                },
                "tag": "tun-inbound"
            },
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                },
                "tag": "socks-inbound"
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "firebase-settings.crashlytics.com",
                            "port": 443,
                            "users": [
                                {
                                    "id": "cxlvin777",
                                    "encryption": "none"
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": "grpc",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "firebase-settings.crashlytics.com",
                        "allowInsecure": True
                    },
                    "grpcSettings": {
                        "serviceName": "cxlvinvl-grpc",
                        "authority": run_app_host
                    }
                }
            },
            {
                "domainStrategy": "AsIs",
                "protocol": "http",
                "settings": {
                    "servers": [
                        {
                            "address": "firebase-settings.crashlytics.com",
                            "port": 8080
                        }
                    ],
                    "headers": {
                        "Host": "CONNECT dynamic-report-api.appsflyer.com:443 HTTP/1.1\r\nx-connected-to: 100.92.0.0/16\r\n\r\n",
                        "Proxy-Connection": "keep-alive",
                        "User-Agent": "cxlvin/1.0",
                        "X-iorg-bsid": "@cxlvinvl-grpc",
                        "X-AppsFlyer-Hosts": "dynamic-report-api.appsflyer.com,conversions.appsflyer.com,inapps.appsflyer.com,events.appsflyer.com,launches.appsflyer.com,gcdsdk.appsflyer.com,cdn-settings.appsflyersdk.com"
                    }
                },
                "tag": "vless-grpc"
            },
            {
                "protocol": "freedom",
                "tag": "direct"
            },
            {
                "protocol": "blackhole",
                "tag": "block"
            }
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "protocol": [
                        "dns"
                    ],
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "inboundTag": [
                        "tun-inbound",
                        "socks-inbound"
                    ],
                    "outboundTag": "proxy"
                }
            ]
        },
        "policy": {
            "levels": {
                "8": {
                    "connIdle": 300,
                    "downlinkOnly": 1,
                    "handshake": 4,
                    "uplinkOnly": 1
                }
            }
        }
    }
    return json.dumps(raw_config, indent=2).encode('utf-8')


class SubHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        host_header = self.headers.get('Host', '')
        
        if self.path == "/raw-config" or self.path.startswith("/raw-config?"):
            config_json = generate_raw_client_config(host_header)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(config_json)
        elif self.path == SECRET_PATH or self.path.startswith(f"{SECRET_PATH}?"):
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

