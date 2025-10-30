#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update.py
- 自动识别 Base64 / Clash YAML / 纯文本 URI
- 新增：订阅分组（有效/失效）
- 节点去重后写入 config.txt
- 所有文件自动创建并写入
- 优化：仅支持 ss, ssr, vmess, vless, trojan, hysteria2, clash 协议
"""
import base64
import os
import re
import sys
import time
import urllib.parse
from typing import List

import requests
import yaml

# ---------- 路径 ----------
REPO_ROOT    = os.path.dirname(os.path.abspath(__file__))
SUB_FILE     = os.path.join(REPO_ROOT, 'sub.txt')
VALID_FILE   = os.path.join(REPO_ROOT, 'sub_valid.txt')
INVALID_FILE = os.path.join(REPO_ROOT, 'sub_invalid.txt')
OUT_FILE     = os.path.join(REPO_ROOT, 'config.txt')

PROTO_FILES = {                 # 协议 → 文件名
    'ss': 'ss.txt',
    'ssr': 'ssr.txt',
    'vmess': 'vmess.txt',
    'vless': 'vless.txt',
    'trojan': 'trojan.txt',
    'hysteria2': 'hysteria2.txt',
    'clash': 'clash.yaml'       # Clash YAML 单独保存/合并
}
ALL_FILE = 'all.txt'           # 总节点文件

TIMEOUT = 10
MAX_RETRIES = 3
MIN_NODES_PER_SUB = 20   # 每条订阅最少节点数，低于此数视为低质量

# ---------- 工具 ----------
def _ensure_files(*paths):
    for p in paths:
        os.makedirs(os.path.dirname(p), exist_ok=True)

def 下载(url: str) -> bytes:
    headers = {'User-Agent': 'Mozilla/5.0'}
    for i in range(MAX_RETRIES):
        try:
            resp = requests.get(url, headers=headers, timeout=TIMEOUT)
            resp.raise_for_status()
            return resp.content
        except Exception as e:
            print(f'[警告] 下载失败：{url}  {e}')
            time.sleep(2)
    return b''

def _try_base64(data: str) -> str:
    data += '=' * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data.encode()).decode('utf-8')
    except Exception:
        return ''

def _clash_to_uri(proxy: dict) -> str:
    t = proxy.get('type', '').lower()
    name = urllib.parse.quote(proxy.get('name', ''))
    server = proxy.get('server', '')
    port = proxy.get('port', 0)
    if not server or not port:
        return ''
    if t == 'ss':
        cipher, pwd = proxy.get('cipher', ''), proxy.get('password', '')
        if not cipher or not pwd:
            return ''
        auth = base64.urlsafe_b64encode(f'{cipher}:{pwd}'.encode()).decode()
        return f'ss://{auth}@{server}:{port}#{name}'
    if t == 'vmess':
        vm = {
            "v": "2", "ps": name, "add": server, "port": str(port),
            "id": proxy.get('uuid', ''), "aid": str(proxy.get('alterId', 0)),
            "net": proxy.get('network', 'tcp'), "type": proxy.get('type', 'none'),
            "host": proxy.get('ws-headers', {}).get('Host', '') or proxy.get('ws-opts', {}).get('headers', {}).get('Host', ''),
            "path": proxy.get('ws-path', '') or proxy.get('ws-opts', {}).get('path', ''),
            "tls": 'tls' if proxy.get('tls', False) else ''
        }
        if not vm['id']:
            return ''
        b64 = base64.urlsafe_b64encode(str(vm).encode()).decode()
        return f'vmess://{b64}'
    if t == 'trojan':
        pwd = proxy.get('password', '')
        if not pwd:
            return ''
        sni = proxy.get('sni', '')
        return f'trojan://{pwd}@{server}:{port}?sni={sni}#{name}'
    if t == 'vless':
        uuid = proxy.get('uuid', '')
        if not uuid:
            return ''
        net = proxy.get('network', 'tcp')
        tls = 'tls' if proxy.get('tls', False) else ''
        host = proxy.get('ws-opts', {}).get('headers', {}).get('Host', '')
        path = proxy.get('ws-opts', {}).get('path', '')
        return f'vless://{uuid}@{server}:{port}?type={net}&security={tls}&host={host}&path={path}#{name}'
    if t == 'hysteria2':
        auth = proxy.get('auth', proxy.get('password', ''))
        if not auth:
            return ''
        alpn = ','.join(proxy.get('alpn', []))
        return f'hysteria2://{auth}@{server}:{port}?alpn={alpn}#{name}'
    return ''

def 提取节点(raw: bytes) -> List[str]:
    if not raw:
        return []
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        text = raw.decode('latin-1')

    # 1. Clash YAML
    for key in ('proxies', 'Proxy', 'proxy-providers'):
        if re.search(rf'^{key}\s*:', text, flags=re.MULTILINE | re.IGNORECASE):
            try:
                data = yaml.safe_load(text)
                proxies = data.get(key, []) if key != 'proxy-providers' else \
                          [p for v in data.get(key, {}).values() for p in v.get('proxies', [])]
                uris = [_clash_to_uri(p) for p in proxies if _clash_to_uri(p)]
                # 为 Clash 协议收集原 YAML（稍后合并写入）
                return uris  # 返回 URI，继续分类
            except Exception:
                return []

    # 2. Base64
    decoded = _try_base64(text)
    if decoded:
        return [ln.strip() for ln in decoded.splitlines() if ln.strip()]

    # 3. 纯文本行
    return [ln.strip() for ln in text.splitlines() if ln.strip()]

def main():
    # 确保目录存在
    for p in (SUB_FILE, VALID_FILE, INVALID_FILE, OUT_FILE, *PROTO_FILES.values()):
        os.makedirs(os.path.dirname(os.path.join(REPO_ROOT, p)), exist_ok=True)

    # 读取订阅
    try:
        links = [ln.strip() for ln in open(SUB_FILE, encoding='utf-8') if ln.strip()]
    except FileNotFoundError:
        links = []

    if not links:
        print('[提示] sub.txt 为空，请添加订阅后重试')
        sys.exit(0)

    # 检测有效性
    valid, invalid = [], []
    for url in links:
        nodes = 提取节点(下载(url))
        if len(nodes) >= MIN_NODES_PER_SUB:  # 优化：使用 MIN_NODES_PER_SUB 阈值
            valid.append(url)
        else:
            invalid.append(url)

    # 写分组文件
    with open(VALID_FILE, 'w', encoding='utf-8') as f:
        f.write(f'# 有效订阅（共 {len(valid)} 条）\n' + '\n'.join(valid) + '\n')
    with open(INVALID_FILE, 'w', encoding='utf-8') as f:
        f.write(f'# 失效订阅（共 {len(invalid)} 条）\n' + '\n'.join(invalid) + '\n')

    print(f'[分组] 有效 {len(valid)} 条')
    print(f'[分组] 失效 {len(invalid)} 条')

    # 协议桶
    protocol_nodes = {proto: [] for proto in PROTO_FILES}
    all_nodes = []
    clash_yamls = []  # 收集 Clash YAML 内容，用于合并

    # 拉取并分类
    for url in valid:
        raw = 下载(url)
        if not raw:
            continue
        text = raw.decode('utf-8', errors='ignore')
        
        # 检查是否为 Clash YAML，并收集原内容
        is_clash = False
        for key in ('proxies', 'Proxy', 'proxy-providers'):
            if re.search(rf'^{key}\s*:', text, flags=re.MULTILINE | re.IGNORECASE):
                is_clash = True
                clash_yamls.append(text)
                break
        
        tmp_nodes = 提取节点(raw)
        all_nodes.extend(tmp_nodes)

        # 按协议分类（仅保留支持协议）
        for node in tmp_nodes:
            if node.startswith('ss://'):
                protocol_nodes['ss'].append(node)
            elif node.startswith('ssr://'):
                protocol_nodes['ssr'].append(node)
            elif node.startswith('vmess://'):
                protocol_nodes['vmess'].append(node)
            elif node.startswith('vless://'):
                protocol_nodes['vless'].append(node)
            elif node.startswith('trojan://'):
                protocol_nodes['trojan'].append(node)
            elif node.startswith('hysteria2://'):
                protocol_nodes['hysteria2'].append(node)
            # 未识别协议忽略，不进 all（但 all 已 extend tmp_nodes）

    # 去重（保序）
    for proto in protocol_nodes:
        protocol_nodes[proto] = list(dict.fromkeys(protocol_nodes[proto]))

    all_nodes = list(dict.fromkeys(all_nodes))

    # 写入各协议文件
    for proto, filename in PROTO_FILES.items():
        if proto == 'clash' and clash_yamls:
            # 合并多个 Clash YAML
            merged_proxies = []
            seen_names = set()
            for yaml_text in clash_yamls:
                try:
                    data = yaml.safe_load(yaml_text)
                    for key in ('proxies', 'Proxy', 'proxy-providers'):
                        proxies = data.get(key, []) if key != 'proxy-providers' else \
                                  [p for v in data.get(key, {}).values() for p in v.get('proxies', [])]
                        for p in proxies:
                            name = p.get('name', '')
                            if name and name not in seen_names:
                                seen_names.add(name)
                                merged_proxies.append(p)
                except Exception:
                    pass
            merged_yaml = {'proxies': merged_proxies}
            with open(os.path.join(REPO_ROOT, filename), 'w', encoding='utf-8') as f:
                yaml.dump(merged_yaml, f, default_flow_style=False, allow_unicode=True)
            print(f'[写入] {filename} : {len(merged_proxies)} 条')
        else:
            with open(os.path.join(REPO_ROOT, filename), 'w', encoding='utf-8') as f:
                f.write('\n'.join(protocol_nodes[proto]) + '\n')
            print(f'[写入] {filename} : {len(protocol_nodes[proto])} 条')

    # 总节点
    with open(os.path.join(REPO_ROOT, ALL_FILE), 'w', encoding='utf-8') as f:
        f.write('\n'.join(all_nodes) + '\n')
    print(f'[完成] {ALL_FILE} : {len(all_nodes)} 条')


if __name__ == '__main__':
    main()
