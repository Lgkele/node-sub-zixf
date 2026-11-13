import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SOURCE_URL = 'https://v2cross.com/5042.html';
const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

const __dirname = dirname(fileURLToPath(import.meta.url));
const subDir = join(__dirname, 'sub');

const res = await fetch(SOURCE_URL, {
  headers: { 'User-Agent': USER_AGENT, Accept: 'text/html,*/*' },
});
if (!res.ok) {
  throw new Error(`Failed to fetch ${SOURCE_URL}: HTTP ${res.status}`);
}
const html = await res.text();

// The page is HTML, so '&' inside links is written as '&amp;'.
// Decode it before extracting, otherwise the links would
// contain a literal '&amp;' and clients would misread the query.
const decodedHtml = html.replace(/&amp;/g, '&');

// Extract every share link on the page, then keep VLESS only.
const allLinks = decodedHtml.match(/(?:vless|vmess|trojan|ss|hysteria2|hy2):\/\/[^\s"'<>`]+/g) ?? [];
const vlessLinks = [...new Set(allLinks.filter((link) => link.startsWith('vless://')))];

// Safety valve: never overwrite a good subscription with a near-empty one.
if (vlessLinks.length < 5) {
  console.error(`Only ${vlessLinks.length} VLESS links extracted (need at least 5); not writing any file.`);
  process.exit(1);
}

const snapshotMatch = decodedHtml.match(/Updated:\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+Tokyo time(?:\s*\(UTC\+9\))?/);
const snapshot = snapshotMatch ? snapshotMatch[0] : null;

const stats = {
  updated: new Date().toISOString(),
  source: SOURCE_URL,
  snapshot,
  count: vlessLinks.length,
};

await mkdir(subDir, { recursive: true });
await writeFile(join(subDir, 'v2cross.txt'), vlessLinks.join('\n') + '\n', 'utf8');
await writeFile(
  join(subDir, 'v2cross-base64.txt'),
  Buffer.from(vlessLinks.join('\n'), 'utf8').toString('base64'),
  'utf8',
);
await writeFile(join(subDir, 'v2cross-stats.json'), JSON.stringify(stats, null, 2) + '\n', 'utf8');

console.log(`Wrote ${vlessLinks.length} VLESS links (snapshot: ${snapshot ?? 'unknown'}).`);
