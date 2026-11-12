#!/usr/bin/env node
/**
 * sync-gist.mjs -- 把三个订阅档案同步到一个 GitHub Gist。
 * 需要环境变量 GIST_ID 与 GIST_TOKEN（仓库 Secrets，绝不写进程式码/日志）。
 * 两者缺一即跳过（exit 0），不令 workflow 失败；上游 fetch-nodes.mjs
 * 用的 vars.GIST_ID / secrets.GIST_PAT 若未设亦不会触发。
 * 成功时 PATCH https://api.github.com/gists/<GIST_ID>，更新三档：
 * base64.txt、clash.yaml、sing-box.json。
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const GIST_ID = process.env.GIST_ID || '';
const TOKEN = process.env.GIST_TOKEN || process.env.GIST_PAT || '';
if (!GIST_ID || !TOKEN) { console.log('gist sync skipped: GIST_ID / GIST_TOKEN not set'); process.exit(0); }
const files = {};
for (const [gistName, repoFile] of [['base64.txt', 'sub/base64.txt'], ['clash.yaml', 'sub/clash.yaml'], ['sing-box.json', 'sub/sing-box.json']]) {
  const content = readFileSync(path.join(HERE, repoFile), 'utf8');
  if (!content.trim()) throw new Error(`empty file, refusing to sync: ${repoFile}`);
  files[gistName] = { content };
}
const res = await fetch(`https://api.github.com/gists/${encodeURIComponent(GIST_ID)}`, {
  method: 'PATCH',
  headers: { Authorization: `Bearer ${TOKEN}`, Accept: 'application/vnd.github+json', 'User-Agent': 'node-sub-zixf' },
  body: JSON.stringify({ files })
});
if (!res.ok) throw new Error(`gist sync failed: HTTP ${res.status} ${await res.text()}`);
const data = await res.json();
console.log(`gist synced: ${data.html_url} files=${Object.keys(data.files || {}).join(',')}`);
