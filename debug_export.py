import json, urllib.parse

d = json.load(open('hy2_tun.json'))
tun_nodes = [o for o in d['outbounds'] if o.get('type') == 'hysteria2']

missing_servers = {'de1.sferavpn.pro', 'hy2.aspidnet.xyz', 'news.gazette.help'}

for n in tun_nodes:
    server = n.get('server', '')
    if server not in missing_servers:
        continue
    
    tag = n.get('tag', '')
    port = n.get('server_port', '')
    password = n.get('password', '')
    sni = n.get('tls', {}).get('server_name', '')
    obfs = n.get('obfs')
    
    print(f"\n=== {tag} ===")
    print(f"  server: {server}")
    print(f"  port: {port}")
    print(f"  password: {repr(password)}")
    print(f"  obfs: {obfs}")
    
    # Simulate v2ray exporter link generation
    query_params = {
        "sni": sni,
        "security": "tls",
        "up": 20,
        "down": 20,
    }
    if obfs and isinstance(obfs, dict):
        obfs_type = obfs.get("type")
        obfs_password = obfs.get("password")
        if obfs_type and obfs_password:
            query_params["obfs"] = obfs_type
            query_params["obfs-password"] = urllib.parse.unquote(obfs_password)
    
    query = urllib.parse.urlencode(query_params)
    fragment = urllib.parse.quote(tag)
    netloc = f"{server}:{port}"
    
    quoted_password = urllib.parse.quote(password, safe='')
    link = f"hysteria2://{quoted_password}@{netloc}?{query}#{fragment}"
    
    print(f"  generated link: {link}")
    
    # Parse it back
    parsed = urllib.parse.urlparse(link)
    print(f"  parsed.username: {repr(parsed.username)}")
    print(f"  MATCH: {parsed.username == password}")
