#!/usr/bin/env node
/**
 * convert.mjs -- 把 sub/v2ray.txt 聚合节点转为 Clash / sing-box 订阅
 * 零第三方依赖，Node 18+。支援 vmess / vless / trojan / ss / hysteria2 / tuic。
 * 安全阀：先在内存里生成并校验两个输出，节点数不足 MIN_NODES（默认 20）
 * 或生成失败时，不写入任何档案（抛错令 workflow 失败、不提交），
 * 保留仓库里上一版已提交的 sub/clash.yaml 与 sub/sing-box.json。
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const MIN_NODES = Number(process.env.MIN_NODES || 20);
const INPUT = path.join(HERE, 'sub', 'v2ray.txt');
const CLASH_OUT = path.join(HERE, 'sub', 'clash.yaml');
const SINGBOX_OUT = path.join(HERE, 'sub', 'sing-box.json');
function decB64(s) {
  s = String(s || '').trim().replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64').toString('utf8');
}
function isB64(s) { return /^[A-Za-z0-9+/=_-]+$/.test(String(s || '').trim()) && String(s).trim().length >= 8; }
function q(v) { return JSON.stringify(String(v ?? '')); }
function num(v, d = 0) { const n = Number(v); return Number.isFinite(n) ? n : d; }
function parseQuery(u) { const o = {}; for (const [k, v] of u.searchParams) o[k] = v; return o; }
function parseSs(line) {
  let rest = line.slice(5); let name = '';
  const hi = rest.indexOf('#'); if (hi >= 0) { name = decodeURIComponent(rest.slice(hi + 1)); rest = rest.slice(0, hi); }
  let left, hostport;
  if (rest.includes('@')) { const at = rest.lastIndexOf('@'); left = rest.slice(0, at); hostport = rest.slice(at + 1); }
  else { const decoded = decB64(rest); const at = decoded.lastIndexOf('@'); left = decoded.slice(0, at); hostport = decoded.slice(at + 1); }
  let cred = left;
  if (isB64(left) && !left.includes(':')) { try { const d = decB64(left); if (d.includes(':')) cred = d; } catch {} }
  if (!cred.includes(':')) return null;
  const [method, ...pw] = cred.split(':'); const password = pw.join(':');
  const [host, portStr] = hostport.split(':');
  if (!host || !num(portStr)) return null;
  return { type: 'ss', name: name || `${host}:${portStr}`, server: host, port: num(portStr), cipher: method, password };
}
function parseNode(line) {
  line = line.trim(); if (!line) return null;
  try {
    if (line.startsWith('vmess://')) {
      const j = JSON.parse(decB64(line.slice(8).split('#')[0]));
      if (!j.add || !j.port) return null;
      return { type: 'vmess', name: j.ps || `${j.add}:${j.port}`, server: j.add, port: num(j.port), uuid: j.id, alterId: num(j.aid, 0), cipher: 'auto', net: j.net || 'tcp', tls: j.tls === 'tls', sni: j.sni || j.host || '', wsPath: j.path || '/', wsHost: j.host || '', grpcService: j.path || '', flow: '' };
    }
    if (line.startsWith('ss://')) return parseSs(line);
    const u = new URL(line); const qs = parseQuery(u);
    const name = decodeURIComponent(u.hash ? u.hash.slice(1) : '') || `${u.hostname}:${u.port}`;
    const base = { name, server: u.hostname, port: num(u.port), tls: qs.security === 'tls' || qs.security === 'reality', sni: qs.sni || qs.peer || u.hostname, net: qs.type || 'tcp', wsPath: qs.path || '/', wsHost: qs.host || '', grpcService: qs.serviceName || '', flow: qs.flow || '' };
    if (line.startsWith('vless://')) return { ...base, type: 'vless', uuid: decodeURIComponent(u.username), reality: qs.security === 'reality', pbk: qs.pbk || '', sid: qs.sid || '' };
    if (line.startsWith('trojan://')) return { ...base, type: 'trojan', password: decodeURIComponent(u.username) };
    if (line.startsWith('hysteria2://') || line.startsWith('hy2://')) return { ...base, type: 'hysteria2', password: decodeURIComponent(u.username), obfs: qs.obfs || '', obfsPassword: qs.obfsPassword || '' };
    if (line.startsWith('tuic://')) { const [uuid, ...pw] = decodeURIComponent(u.username).split(':'); return { ...base, type: 'tuic', uuid, password: pw.join(':') }; }
  } catch { return null; }
  return null;
}
const raw = readFileSync(INPUT, 'utf8');
const seen = new Set(); const nodes = []; const skipped = {};
for (const line of raw.split(/\r?\n/)) {
  const n = parseNode(line); if (!n) { const k = line.trim().slice(0, line.indexOf('://') + 3) || 'empty'; skipped[k] = (skipped[k] || 0) + 1; continue; }
  let name = n.name || 'node'; if (seen.has(name)) { let i = 2; while (seen.has(`${name} #${i}`)) i++; name = `${name} #${i}`; }
  seen.add(name); n.name = name; nodes.push(n);
}
console.log(`parsed=${nodes.length} skipped=${JSON.stringify(skipped)}`);
if (nodes.length < MIN_NODES) throw new Error(`too few convertible nodes: ${nodes.length} < MIN_NODES=${MIN_NODES}; keeping previous outputs`);
function clashProxy(n) {
  const L = [`  - name: ${q(n.name)}`, `    type: ${n.type === 'ss' ? 'ss' : n.type}`, `    server: ${q(n.server)}`, `    port: ${n.port}`, '    udp: true'];
  if (n.type === 'vmess') { L.push(`    uuid: ${q(n.uuid)}`, `    alterId: ${n.alterId}`, '    cipher: auto'); }
  if (n.type === 'vless') { L.push(`    uuid: ${q(n.uuid)}`); if (n.flow) L.push(`    flow: ${q(n.flow)}`); }
  if (n.type === 'trojan') L.push(`    password: ${q(n.password)}`);
  if (n.type === 'ss') L.push(`    cipher: ${q(n.cipher)}`, `    password: ${q(n.password)}`);
  if (n.type === 'hysteria2') { L.push(`    password: ${q(n.password)}`); if (n.obfs) L.push(`    obfs: ${q(n.obfs)}`, `    obfs-password: ${q(n.obfsPassword)}`); }
  if (n.type === 'tuic') L.push(`    uuid: ${q(n.uuid)}`, `    password: ${q(n.password)}`, '    alpn: [h3]', '    congestion-controller: bbr');
  if (n.type === 'vmess' || n.type === 'vless' || n.type === 'trojan') {
    if (n.tls) { L.push('    tls: true'); if (n.sni) L.push(`    servername: ${q(n.sni)}`); if (n.reality) { L.push('    reality-opts:', `      public-key: ${q(n.pbk)}`); if (n.sid) L.push(`      short-id: ${q(n.sid)}`); } }
    if (n.net && n.net !== 'tcp') {
      L.push(`    network: ${q(n.net)}`);
      if (n.net === 'ws') { L.push('    ws-opts:', `      path: ${q(n.wsPath)}`); if (n.wsHost) L.push('      headers:', `        Host: ${q(n.wsHost)}`); }
      if (n.net === 'grpc') L.push('    grpc-opts:', `      grpc-service-name: ${q(n.grpcService)}`);
    }
  }
  if (n.type === 'hysteria2' && n.sni) L.push(`    sni: ${q(n.sni)}`);
  if (n.type === 'tuic' && n.sni) L.push(`    sni: ${q(n.sni)}`);
  return L.join('\n');
}
const names = nodes.map((n) => n.name);
const clash = [
  'port: 7890', 'socks-port: 7891', 'allow-lan: false', 'mode: rule', 'log-level: info',
  'external-controller: 127.0.0.1:9090',
  'dns:', '  enable: true', '  nameserver:', '    - 223.5.5.5', '    - 8.8.8.8',
  'proxies:', ...nodes.map(clashProxy),
  'proxy-groups:',
  '  - name: PROXY', '    type: url-test',
  `    proxies: [${names.map(q).join(', ')}]`,
  '    url: http://www.gstatic.com/generate_204', '    interval: 300', '    tolerance: 50',
  '  - name: Auto', '    type: select', '    proxies: [PROXY, DIRECT]',
  'rules:', '  - MATCH,PROXY', ''
].join('\n');
function sbTransport(n) {
  if (n.net === 'ws') { const t = { type: 'ws', path: n.wsPath || '/' }; if (n.wsHost) t.headers = { Host: n.wsHost }; return t; }
  if (n.net === 'grpc') return { type: 'grpc', service_name: n.grpcService || '' };
  return undefined;
}
function sbTls(n) { return n.tls ? { enabled: true, server_name: n.sni || n.server, insecure: false } : undefined; }
function sbNode(n) {
  const o = { tag: n.name, server: n.server, server_port: n.port };
  if (n.type === 'vmess') { o.type = 'vmess'; o.uuid = n.uuid; o.security = 'auto'; o.alter_id = n.alterId; const t = sbTransport(n); if (t) o.transport = t; const tls = sbTls(n); if (tls) o.tls = tls; }
  if (n.type === 'vless') { o.type = 'vless'; o.uuid = n.uuid; if (n.flow) o.flow = n.flow; const t = sbTransport(n); if (t) o.transport = t; const tls = sbTls(n); if (tls) o.tls = tls; }
  if (n.type === 'trojan') { o.type = 'trojan'; o.password = n.password; const t = sbTransport(n); if (t) o.transport = t; const tls = sbTls(n); if (tls) o.tls = tls; }
  if (n.type === 'ss') { o.type = 'shadowsocks'; o.method = n.cipher; o.password = n.password; }
  if (n.type === 'hysteria2') { o.type = 'hysteria2'; o.password = n.password; const tls = sbTls(n); o.tls = tls || { enabled: true, server_name: n.sni || n.server, insecure: false }; if (n.obfs) { o.obfs = { type: n.obfs, password: n.obfsPassword || '' }; } }
  if (n.type === 'tuic') { o.type = 'tuic'; o.uuid = n.uuid; o.password = n.password; o.congestion_control = 'bbr'; o.tls = sbTls(n) || { enabled: true, server_name: n.sni || n.server, insecure: false }; }
  return o;
}
const singbox = {
  log: { level: 'info' },
  dns: { servers: [{ tag: 'dns', address: '223.5.5.5' }] },
  inbounds: [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 }],
  outbounds: [...nodes.map(sbNode), { type: 'selector', tag: 'PROXY', outbounds: names }, { type: 'urltest', tag: 'Auto', outbounds: names, url: 'https://www.gstatic.com/generate_204', interval: '5m' }, { type: 'direct', tag: 'direct' }, { type: 'block', tag: 'block' }],
  route: { rules: [], final: 'PROXY', auto_detect_interface: true }
};
const singboxText = JSON.stringify(singbox, null, 2) + '\n';
JSON.parse(singboxText);
if (!clash.includes('proxy-groups:') || !clash.includes('url-test')) throw new Error('clash output missing proxy group');
mkdirSync(path.join(HERE, 'sub'), { recursive: true });
writeFileSync(CLASH_OUT, clash);
writeFileSync(SINGBOX_OUT, singboxText);
console.log(`wrote ${CLASH_OUT} (${nodes.length} proxies)`);
console.log(`wrote ${SINGBOX_OUT} (${nodes.length} outbounds)`);
