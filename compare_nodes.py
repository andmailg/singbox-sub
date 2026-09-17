import json, urllib.parse

# Read hy2_tun.json nodes
d = json.load(open('hy2_tun.json'))
tun_nodes = [o for o in d['outbounds'] if o.get('type') == 'hysteria2']

# Read hy2.txt nodes
with open('hy2.txt', encoding='utf-8') as f:
    v2ray_lines = [l.strip() for l in f if l.strip()]

# Build lookup by server:port
tun_lookup = {}
for n in tun_nodes:
    key = f"{n['server']}:{n['server_port']}"
    tun_lookup[key] = n['tag']

v2ray_lookup = {}
for line in v2ray_lines:
    parsed = urllib.parse.urlparse(line)
    server = parsed.hostname or ''
    port = parsed.port or ''
    key = f'{server}:{port}'
    v2ray_lookup[key] = urllib.parse.unquote(parsed.fragment or '')

# Find missing
tun_keys = set(tun_lookup.keys())
v2ray_keys = set(v2ray_lookup.keys())
missing = tun_keys - v2ray_keys
extra = v2ray_keys - tun_keys

print(f'tun nodes: {len(tun_nodes)}, v2ray lines: {len(v2ray_lines)}')
print(f'Missing from v2ray ({len(missing)}):')
for k in sorted(missing):
    print(f'  {tun_lookup[k]} -> {k}')
print(f'Extra in v2ray ({len(extra)}):')
for k in sorted(extra):
    print(f'  {v2ray_lookup.get(k, "?")} -> {k}')
