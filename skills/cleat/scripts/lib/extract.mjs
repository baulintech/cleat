// Inventory: walk a skill folder and list everything it reaches outside
// itself (URLs, downloads, package installs), including references hidden in
// HTML comments, base64 blobs and invisible Unicode.
import { readdir, readFile, lstat, readlink } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, relative, sep } from 'node:path';
import net from 'node:net';
import { sha256, lineIndex, logicalLine, excerpt, maxSeverity, bump, rank, CONTINUES } from './util.mjs';
import { scanContent, RULES } from './flags.mjs';

const SKIP_DIRS = new Set(['.git', '.cleat']);
const MAX_TEXT_BYTES = 2 * 1024 * 1024;
const MAX_FILES = 5000;

function hashStream(path) {
  return new Promise((resolve, reject) => {
    const h = createHash('sha256');
    createReadStream(path)
      .on('data', (c) => h.update(c))
      .on('error', reject)
      .on('end', () => resolve(h.digest('hex')));
  });
}

// Every file is either read as text, or listed as something Cleat could not
// look inside. Nothing is skipped silently.
export async function walkSkill(root) {
  const files = [];
  const notes = [];
  let capped = false;
  async function walk(dir) {
    const entries = (await readdir(dir, { withFileTypes: true })).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    for (const entry of entries) {
      if (files.length >= MAX_FILES) {
        if (!capped) notes.push(`Stopped after ${MAX_FILES} files. The rest of the folder was not inspected.`);
        capped = true;
        return;
      }
      const full = join(dir, entry.name);
      const rel = relative(root, full).split(sep).join('/');
      if (entry.isSymbolicLink()) {
        let target = '';
        try { target = await readlink(full); } catch { /* unreadable link */ }
        files.push({ path: rel, kind: 'symlink', target, bytes: 0, sha256: sha256(`symlink:${target}`) });
      } else if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) await walk(full);
      } else if (!entry.isFile()) {
        files.push({ path: rel, kind: 'opaque', reason: 'not a regular file', bytes: 0, sha256: null });
      } else {
        const st = await lstat(full);
        if (st.size > MAX_TEXT_BYTES) {
          files.push({ path: rel, kind: 'opaque', reason: 'larger than 2 MiB', bytes: st.size, sha256: await hashStream(full) });
        } else {
          const buf = await readFile(full);
          const isText = !buf.subarray(0, 8000).includes(0);
          files.push({
            path: rel,
            kind: isText ? 'text' : 'opaque',
            reason: isText ? undefined : 'binary',
            bytes: buf.length,
            sha256: sha256(buf),
            text: isText ? buf.toString('utf8') : undefined,
          });
        }
      }
    }
  }
  await walk(root);
  const treeSha256 = sha256(files.map((f) => `${f.path}\0${f.sha256}\n`).join(''));
  return { files, notes, treeSha256 };
}

// ---------------------------------------------------------------- URLs

const URL_RE = /\bhttps?:\/\/[^\s<>"'`)\]\\]+/gi;
const FETCH_CMD = /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b([^\n|;&]{0,400})/gi;
const HOSTISH = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}(?::\d{1,5})?(?:\/\S*)?$/i;
const FILE_EXT = new Set(['sh', 'py', 'js', 'ts', 'json', 'txt', 'md', 'zip', 'gz', 'tar', 'tgz', 'exe', 'ps1', 'yaml', 'yml', 'toml', 'html', 'log', 'pem', 'key', 'csv', 'xml', 'bin', 'deb', 'rpm', 'dmg', 'pkg', 'msi']);
const VALUE_FLAGS = new Set(['-o', '--output', '-outfile', '-h', '--header', '-d', '--data', '-a', '--user-agent', '-e', '--referer', '-u', '--user', '-x', '--request', '-b', '--cookie', '-t', '-f', '--form']);

const EXEC_RE = [
  RULES.find((r) => r.id === 'pipe-to-shell').re,
  /(?:\b(?:(?:ba|z)?sh|source|eval)\b|(?:^|\s)\.)\s+(?:-c\s+)?["']?(?:<\(|\$\()\s*(?:curl|wget)\b/i,
  /\b(?:iex|invoke-expression)\b/i,
];
const DOWNLOAD_RE = /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|git\s+clone|pip3?\s+install|npm\s+(?:i|install)|npx|uvx|go\s+install|docker\s+(?:pull|run)|start-bitstransfer|certutil|bitsadmin|aria2c)\b/i;
const INSTRUCT_RE = /\b(?:read|fetch|follow|open|visit|load|consult|retrieve|download|install|run|execute|go\s+to|browse|navigate|check|see|refer|get|use)\b/i;
export const USAGE_ORDER = ['mention', 'instruction', 'download', 'execute'];
const UPLOAD_RE = RULES.find((r) => r.id === 'data-upload').re;
const SECRET_RE = new RegExp(RULES.filter((r) => r.id === 'credential-access' || r.id === 'env-harvest').map((r) => r.re.source).join('|'), 'i');

// Data files (tables, JSON, lockfiles) hold links as values, not as
// directions to the agent. Links there are still listed and locked, but only
// a run command counts as use.
const DATA_FILE = /\.(?:csv|tsv|json|jsonl|ndjson|lock)$/i;

function classifyUsage(line, file = '') {
  if (EXEC_RE.some((re) => re.test(line))) return 'execute';
  if (DATA_FILE.test(file)) return 'mention';
  if (DOWNLOAD_RE.test(line)) return 'download';
  if (INSTRUCT_RE.test(line)) return 'instruction';
  return 'mention';
}

const PASTE_HOSTS = ['pastebin.com', 'glot.io', 'hastebin.com', 'paste.ee', 'ghostbin.com', 'rentry.co', 'rentry.org', 'dpaste.com', 'dpaste.org', 'termbin.com', 'ix.io', '0x0.st', 'transfer.sh', 'file.io', 'catbox.moe', 'pastes.io', 'privatebin.net', 'controlc.com', 'justpaste.it', 'paste.rs', 'sprunge.us', 'gist.githubusercontent.com'];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at', 'ow.ly', 'buff.ly', 'tiny.cc', 't.ly', 'rebrand.ly'];
const COLLECTORS = ['ngrok.io', 'ngrok-free.app', 'ngrok.app', 'trycloudflare.com', 'loca.lt', 'serveo.net', 'localhost.run', 'webhook.site', 'requestbin.com', 'pipedream.net', 'interact.sh', 'oast.fun', 'oast.pro', 'oast.live', 'burpcollaborator.net', 'beeceptor.com', 'requestcatcher.com', 'duckdns.org'];
const RESERVED_TLDS = /\.(?:example|test|invalid|localhost|local|internal)$/i;
const RESERVED_HOSTS = new Set(['example.com', 'example.org', 'example.net', 'localhost']);

const onList = (host, list) => list.some((h) => host === h || host.endsWith(`.${h}`));

function urlFlags(u, { schemeless }) {
  const flags = [];
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const add = (id, severity, why) => flags.push({ id, severity, why });
  if (net.isIP(host)) {
    if (isLocalIp(host)) add('local-address', 'info', 'A local or private address, usually a development server on the same machine. Not fetched.');
    else add('raw-ip', 'high', 'Points at a bare IP address instead of a named site.');
  }
  if (onList(host, PASTE_HOSTS)) add('paste-site', 'high', 'Hosted on a paste or snippet site, where anyone can post and the content can be swapped at any time.');
  if (onList(host, SHORTENERS)) add('url-shortener', 'medium', 'A link shortener hides the real destination, and the destination can be changed later.');
  if (onList(host, COLLECTORS)) add('tunnel-or-collector', 'high', 'A temporary tunnel or request-collection service, often used to receive stolen data.');
  if (/discord(?:app)?\.com$/.test(host) && /\/api\/webhooks\//.test(u.pathname)) add('chat-webhook', 'high', 'A Discord webhook: a write-only drop box often used to receive stolen data.');
  if (host === 'api.telegram.org' && /\/bot/.test(u.pathname)) add('chat-webhook', 'high', 'A Telegram bot endpoint, often used to receive stolen data.');
  if (host === 'hooks.slack.com') add('chat-webhook', 'medium', 'A Slack incoming webhook that can receive data.');
  if (/(?:^|\.)xn--/.test(host)) add('lookalike-domain', 'high', 'The domain uses non-Latin characters that can imitate a trusted name.');
  if (u.username || u.password) add('credentials-in-url', 'medium', 'The link carries a username or password, sometimes used to disguise the real host.');
  if (u.port && !['80', '443'].includes(u.port)) add('unusual-port', 'low', `Uses port ${u.port} instead of the normal web ports.`);
  if (u.protocol === 'http:') add('plain-http', schemeless ? 'medium' : 'low', 'Not encrypted, so the content can be altered in transit.');
  if (/\.(?:sh|bash|ps1|bat|cmd|exe|msi|dmg|pkg|deb|rpm|appimage|scr|jar|zip|7z|rar|tar|tgz|gz)$/i.test(u.pathname)) add('executable-or-archive', 'medium', 'The link is to a script, installer or archive.');

  // Is the content address fixed, or can the owner change it under the same link?
  let immutable = false;
  const seg = u.pathname.split('/').filter(Boolean);
  const isSha = (s) => /^[0-9a-f]{40}$/i.test(s || '');
  if (host === 'raw.githubusercontent.com') {
    immutable = isSha(seg[2]);
    if (!immutable) add('mutable-git-ref', 'low', 'Follows a branch or tag, so the file can change without the link changing.');
  } else if (host === 'github.com' && ['blob', 'raw', 'tree'].includes(seg[2])) {
    immutable = isSha(seg[3]);
    if (!immutable) add('mutable-git-ref', 'low', 'Follows a branch or tag, so the file can change without the link changing.');
  } else if (host === 'github.com' && seg[2] === 'releases' && seg[3] === 'latest') {
    add('mutable-git-ref', 'low', 'Always resolves to the newest release, whatever that becomes.');
  } else if (host === 'gist.githubusercontent.com') {
    immutable = isSha(seg[3]);
  }
  return { flags, immutable };
}

function isLocalIp(host) {
  return /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0$|169\.254\.)/.test(host) || host === '::1' || host === '::';
}

function isReserved(u) {
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (net.isIP(host) && isLocalIp(host)) return true;
  if (RESERVED_HOSTS.has(host) || RESERVED_TLDS.test(host) || !host.includes('.')) return true;
  return onList(host, ['example.com', 'example.org', 'example.net']);
}

// ------------------------------------------------------------ packages

const NAME = {
  npm: /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/,
  pypi: /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/,
  docker: /^[a-z0-9][a-z0-9._/-]*$/i,
  go: /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\/\S+$/i,
  other: /^[A-Za-z0-9][A-Za-z0-9._+/-]*$/,
};
const GIT_SOURCE = /^(?:github:|gitlab:|bitbucket:|git\+|git:\/\/)/i;
const STOPWORDS = new Set(['to', 'and', 'or', 'the', 'a', 'an', 'is', 'are', 'for', 'with', 'command', 'commands', 'will', 'can', 'if', 'then', 'in', 'on', 'it', 'as', 'be', 'by', 'from', 'that', 'this', 'which', 'when', 'you', 'your', 'not', 'so', 'at', 'of', 'run', 'runs', 'install', 'instead', 'directly', 'itself', 'here', 'below', 'above', 'works', 'does', 'also', 'but', 'like', 'via', 'script', 'scripts', 'package', 'packages', 'tool', 'tools', 'installs', 'installed', 'installing', 'stays', 'step', 'first', 'once', 'now', 'only', 'these', 'those', 'them', 'all']);

const INSTALLERS = [
  { eco: 'npm', exec: true, first: true, re: /\b(?:npx|pnpm\s+dlx|yarn\s+dlx|bunx|bun\s+x)\s+([^\n|;&`]*)/gi, valued: ['-c', '--call'], pkgFlags: ['-p', '--package'] },
  { eco: 'npm', re: /\b(?:npm\s+(?:i|install|add)|pnpm\s+(?:add|install|i)|yarn\s+(?:global\s+)?add|bun\s+(?:add|install|i))\s+([^\n|;&`]*)/gi, valued: ['--prefix', '--tag'], indexFlags: ['--registry'] },
  { eco: 'pypi', re: /\b(?:pip3?|python3?\s+-m\s+pip|py\s+-m\s+pip|uv\s+pip)\s+install\s+([^\n|;&`]*)/gi, valued: ['-r', '--requirement', '-c', '--constraint', '-e', '--editable', '-t', '--target', '--python', '-f', '--find-links'], indexFlags: ['-i', '--index-url', '--extra-index-url'] },
  { eco: 'pypi', exec: true, first: true, re: /\b(?:uvx|pipx\s+(?:run|install)|uv\s+tool\s+(?:run|install))\s+([^\n|;&`]*)/gi, valued: ['--python', '--with'], pkgFlags: ['--from'] },
  { eco: 'brew', re: /\bbrew\s+install\s+([^\n|;&`]*)/gi },
  { eco: 'cargo', re: /\bcargo\s+install\s+([^\n|;&`]*)/gi, valued: ['--version', '--git', '--branch', '--tag', '--rev', '--path', '--root'] },
  { eco: 'go', exec: true, first: true, re: /\bgo\s+(?:install|run)\s+([^\n|;&`]*)/gi },
  { eco: 'gem', re: /\bgem\s+install\s+([^\n|;&`]*)/gi, valued: ['-v', '--version', '--source'] },
  { eco: 'docker', exec: true, first: true, re: /\bdocker\s+(?:pull|run)\s+([^\n|;&`]*)/gi, valued: ['-v', '--volume', '-e', '--env', '-p', '--publish', '--name', '-w', '--workdir', '--network', '-u', '--user', '--entrypoint', '--platform', '-m', '--memory', '--mount', '--env-file', '-l', '--label', '-h', '--hostname', '--cpus'] },
];

function parseSpec(eco, token) {
  if (GIT_SOURCE.test(token)) {
    return { name: token, version: null, pinned: /#[0-9a-f]{40}$/i.test(token), source: 'git' };
  }
  if (eco === 'npm') {
    const at = token.lastIndexOf('@');
    const name = at > 0 ? token.slice(0, at) : token;
    const version = at > 0 ? token.slice(at + 1) : null;
    if (!NAME.npm.test(name)) return null;
    return { name, version, pinned: /^\d+\.\d+\.\d+(?:-[\w.]+)?$/.test(version || '') };
  }
  if (eco === 'pypi') {
    const m = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?(?:(==|>=|<=|~=|!=|>|<)(.+))?$/.exec(token);
    if (!m || !NAME.pypi.test(m[1])) return null;
    return { name: m[1].toLowerCase(), version: m[3] || null, pinned: m[2] === '==' && !/\*/.test(m[3] || '') };
  }
  if (eco === 'docker') {
    const [ref, digest] = token.split('@');
    if (!NAME.docker.test(ref.split(':')[0])) return null;
    const colon = ref.lastIndexOf(':');
    const hasTag = colon > ref.lastIndexOf('/');
    return { name: hasTag ? ref.slice(0, colon) : ref, version: digest || (hasTag ? ref.slice(colon + 1) : null), pinned: Boolean(digest) };
  }
  if (eco === 'go') {
    const [path, version] = token.split('@');
    if (!NAME.go.test(path)) return null;
    return { name: path, version: version || null, pinned: Boolean(version) && version !== 'latest' && /^v?\d|^[0-9a-f]{7,40}$/.test(version) };
  }
  const at = token.lastIndexOf('@');
  const name = at > 0 ? token.slice(0, at) : token;
  if (!NAME.other.test(name)) return null;
  return { name, version: at > 0 ? token.slice(at + 1) : null, pinned: null };
}

// Package-manager CLIs that install agent skills. Knowing the package is not
// enough for the person approving the command: they need to know which skill
// it will install, and whether it will do so without asking.
const SKILL_CLIS = new Set(['skills']);
const SKILLS_SUBCOMMANDS = {
  search: ['find', 'search', 'f', 's'],
  install: ['add', 'a', 'install', 'i'],
  use: ['use'],
  update: ['update', 'upgrade', 'check'],
  remove: ['remove', 'rm', 'r'],
  list: ['list', 'ls'],
  create: ['init'],
  sync: ['sync', 'experimental_sync', 'experimental_install'],
};
const SKILLS_VALUED = new Set(['-a', '--agent', '-s', '--skill', '--owner', '--rename', '--metadata', '--include', '--exclude']);

function parseSkillsCommand(args) {
  const clean = args.map((t) => t.replace(/^["']|["',.;:)]+$/g, ''));
  const sub = (clean[0] || '').toLowerCase();
  const kind = Object.keys(SKILLS_SUBCOMMANDS).find((k) => SKILLS_SUBCOMMANDS[k].includes(sub)) || (sub ? 'other' : 'none');
  const action = { cli: 'skills', subcommand: sub || null, kind, target: null, targetLater: false, skills: [], global: false, noConfirm: false };
  const positional = [];
  for (let i = 1; i < clean.length; i++) {
    const t = clean[i];
    if (!t) continue;
    if (t === '-g' || t === '--global') { action.global = true; continue; }
    if (t === '-y' || t === '--yes') { action.noConfirm = true; continue; }
    if (t === '--all') { action.noConfirm = true; action.skills.push('*'); continue; }
    if (t === '-s' || t === '--skill') {
      while (clean[i + 1] && !clean[i + 1].startsWith('-')) action.skills.push(clean[++i]);
      continue;
    }
    if (SKILLS_VALUED.has(t)) {
      while (clean[i + 1] && !clean[i + 1].startsWith('-')) i++;
      continue;
    }
    if (t.startsWith('-')) continue;
    positional.push(t);
  }
  if (kind === 'search') {
    const q = positional.join(' ');
    action.query = q && !/[<>\[\]]/.test(q) ? q : null;
    action.queryLater = Boolean(q) && action.query === null;
  }
  if (kind === 'install' || kind === 'use') {
    const src = positional[0] || null;
    if (!src || /[<>\[\]]/.test(src)) {
      action.targetLater = true;
      action.placeholder = src;
    } else {
      const at = src.lastIndexOf('@');
      const repo = at > 0 && !src.includes('://') ? src.slice(0, at) : src;
      if (at > 0 && !src.includes('://')) action.skills.unshift(src.slice(at + 1));
      action.target = repo;
    }
  }
  return action;
}

function parseInstalls(segment, prose) {
  const out = { packages: [], customIndex: false };
  for (const spec of INSTALLERS) {
    if (prose && !spec.exec) continue;
    spec.re.lastIndex = 0;
    let m;
    while ((m = spec.re.exec(segment))) {
      const tokens = m[1].trim().split(/\s+/).filter(Boolean);
      let skipNext = false;
      let takeNext = false;
      for (let ti = 0; ti < tokens.length; ti++) {
        const raw = tokens[ti];
        let token = raw.replace(/^["']|["',.;:)]+$/g, '');
        if (skipNext) { skipNext = false; continue; }
        if (token.startsWith('-') && !takeNext) {
          const [flag, value] = token.split(/=(.*)/s);
          if (spec.indexFlags?.includes(flag)) { out.customIndex = true; if (value === undefined) skipNext = true; continue; }
          if (spec.pkgFlags?.includes(flag)) {
            if (value === undefined) { takeNext = true; continue; }
            token = value;
          } else {
            if (spec.valued?.includes(flag) && value === undefined) skipNext = true;
            continue;
          }
        }
        takeNext = false;
        const endsSentence = /[.;:]["')]*$/.test(raw);
        if (!token || /^[.~/$%]|:\/\/|\\|^\w:\\/.test(token) || /\.(?:go|py|js|ts|txt|json|toml|whl|tgz)$/i.test(token)) {
          if (spec.first) break;
          continue;
        }
        if (STOPWORDS.has(token.toLowerCase()) || (prose && !/[a-z]/i.test(token))) break;
        const parsed = parseSpec(spec.eco, token);
        if (parsed) {
          const pkg = { eco: spec.eco, exec: Boolean(spec.exec), ...parsed, spec: token };
          if (spec.eco === 'npm' && spec.exec && SKILL_CLIS.has(parsed.name)) pkg.action = parseSkillsCommand(tokens.slice(ti + 1));
          out.packages.push(pkg);
        }
        if (spec.first || prose || endsSentence) break;
      }
    }
  }
  return out;
}

// --------------------------------------------------- hidden content

const INVISIBLE_ALL = /[\u200B-\u200F\u2060-\u2064\u202A-\u202E\u2066-\u2069\u00AD\uFEFF]/g;
const INVISIBLE_FLAG = /[\u200B\u200E\u200F\u2060-\u2064\u202A-\u202E\u2066-\u2069\uFEFF]/g;
const TAG_RUN = /[\u{E0000}-\u{E007F}]+/gu;
const B64_RE = /[A-Za-z0-9+/]{40,}={0,2}/g;

function decodeTags(run) {
  let s = '';
  for (const ch of run) {
    const cp = ch.codePointAt(0) - 0xe0000;
    if (cp >= 0x20 && cp <= 0x7e) s += String.fromCharCode(cp);
  }
  return s;
}

function commentRanges(text) {
  const ranges = [];
  let pos = 0;
  for (;;) {
    const start = text.indexOf('<!--', pos);
    if (start === -1) break;
    const end = text.indexOf('-->', start + 4);
    if (end === -1) { ranges.push([start, text.length]); break; }
    ranges.push([start, end + 3]);
    pos = end + 3;
  }
  // Markdown "link reference" comments: [//]: # (hidden text)
  const ref = /^\[[^\]\n]{0,40}\]:\s*#[^\n]*$/gm;
  let m;
  while ((m = ref.exec(text))) ranges.push([m.index, m.index + m[0].length]);
  return ranges;
}

// Pull references out of one block of text. Recurses (to a small depth) into
// text that was hidden inside base64 or Unicode tag characters.
function extractText(raw, ctx) {
  const { file, isMarkup = false, layer = null, depth = 0, lineOverride = null } = ctx;
  const out = { urls: [], packages: [], findings: [] };
  const merge = (other) => {
    out.urls.push(...other.urls);
    out.packages.push(...other.packages);
    out.findings.push(...other.findings);
  };
  let text = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;

  const rawIdx = lineIndex(text);
  const rawLine = (offset) => lineOverride ?? rawIdx.lineOf(offset);
  for (const m of text.matchAll(TAG_RUN)) {
    const decoded = decodeTags(m[0]);
    if (decoded.length < 3) continue;
    const line = rawLine(m.index);
    out.findings.push({
      id: 'hidden-unicode-text', severity: 'high', file, line, layer,
      why: 'Invisible Unicode "tag" characters spell out text that a person cannot see but an agent can read.',
      excerpt: excerpt(decoded),
    });
    for (const f of scanContent(decoded)) {
      out.findings.push({ id: f.id, severity: f.severity, why: f.why, file, line, layer: 'unicode-tags', excerpt: f.samples[0]?.excerpt });
    }
    if (depth < 2) merge(extractText(decoded, { ...ctx, layer: 'unicode-tags', depth: depth + 1, lineOverride: line }));
  }
  const invisible = [...text.matchAll(INVISIBLE_FLAG)];
  if (invisible.length) {
    out.findings.push({
      id: 'invisible-characters', severity: 'medium', file, line: rawLine(invisible[0].index), layer,
      why: `${invisible.length} zero-width or direction-control character(s), which can hide or reorder text.`,
    });
  }

  const clean = text.replace(TAG_RUN, '').replace(INVISIBLE_ALL, '');
  const idx = lineIndex(clean);
  const lineAt = (offset) => lineOverride ?? idx.lineOf(offset);
  const hiddenRanges = isMarkup ? commentRanges(clean) : [];
  const hiddenAt = (offset) =>
    layer || (hiddenRanges.some(([a, b]) => offset >= a && offset < b) ? 'html-comment' : null);

  // URLs with a scheme
  for (const m of clean.matchAll(URL_RE)) {
    let value = m[0].replace(/[.,;:!?*_~|]+$/, '');
    let templated = false;
    const cut = value.search(/\$[{(A-Za-z_]|\{|%7B/i);
    if (cut !== -1) {
      templated = true;
      const hostEnd = value.indexOf('/', value.indexOf('://') + 3);
      if (/^https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?:[:/]|$)/i.test(value)) continue;
      if (hostEnd === -1 || cut < hostEnd) {
        out.findings.push({
          id: 'dynamic-url', severity: 'medium', file, line: lineAt(m.index), layer,
          why: 'A URL whose host is assembled at run time, so its destination cannot be listed in advance.',
          excerpt: excerpt(m[0]),
        });
        continue;
      }
      value = value.slice(0, cut);
    }
    let u;
    try { u = new URL(value); } catch { continue; }
    u.hash = '';
    const line = lineAt(m.index);
    const context = logicalLine(idx, idx.lineOf(m.index));
    out.urls.push({
      url: u.href, file, line, templated, schemeless: false,
      usage: classifyUsage(context, file), upload: UPLOAD_RE.test(context), secrets: SECRET_RE.test(context), hidden: hiddenAt(m.index), excerpt: excerpt(context),
    });
  }

  // Download commands aimed at a bare host with no scheme in front of it
  for (const m of clean.matchAll(FETCH_CMD)) {
    const tokens = m[1].trim().split(/\s+/);
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i].replace(/^["']|["']$/g, '');
      const prev = (tokens[i - 1] || '').toLowerCase();
      if (!token || token.startsWith('-') || token.includes('://') || VALUE_FLAGS.has(prev)) continue;
      if (!HOSTISH.test(token)) continue;
      if (!token.includes('/') && FILE_EXT.has(token.split('.').pop().split(':')[0].toLowerCase())) continue;
      let u;
      try { u = new URL(`http://${token}`); } catch { continue; }
      const context = logicalLine(idx, idx.lineOf(m.index));
      out.urls.push({
        url: u.href, file, line: lineAt(m.index), templated: false, schemeless: true,
        usage: classifyUsage(context, file), upload: UPLOAD_RE.test(context), secrets: SECRET_RE.test(context), hidden: hiddenAt(m.index), excerpt: excerpt(context),
      });
    }
  }

  // Package installs. In Markdown, commands count when they are in code;
  // in prose only run-on-fetch tools (npx, uvx and friends) count.
  let inFence = false;
  // Is this line under a lead-in such as "For example:" or "Example response:"?
  // Commands there illustrate what a user might see; they are not steps the
  // agent is told to take.
  let exampleContext = false;
  for (let n = 1; n <= idx.count; n++) {
    const lineText = idx.lineText(n);
    const segments = [];
    if (isMarkup && /^\s*(?:```|~~~)/.test(lineText)) { inFence = !inFence; continue; }
    if (isMarkup && !inFence) {
      const t = lineText.trim();
      if (/^#{1,6}\s/.test(t)) exampleContext = false;
      else if (t && !/^(?:[-*+]|\d+[.)])\s/.test(t)) exampleContext = /:\**\s*$/.test(t) && /\bexamples?\b|\be\.g\./i.test(t);
    }
    if (!isMarkup || inFence || layer) {
      if (n > 1 && CONTINUES.test(idx.lineText(n - 1)) && (!isMarkup || inFence)) continue;
      // A comment line in a script is prose, even when it mentions a command.
      const comment = !isMarkup && /^\s*(?:\/\/|#(?!!)|\/?\*|--\s|<!--)/.test(lineText);
      segments.push({ text: isMarkup && !inFence ? lineText : logicalLine(idx, n), prose: comment });
    } else {
      let rest = lineText;
      for (const span of lineText.matchAll(/`([^`\n]+)`/g)) {
        segments.push({ text: span[1], prose: false });
        rest = rest.replace(span[0], ' ');
      }
      segments.push({ text: rest, prose: true });
    }
    for (const seg of segments) {
      if (seg.text.length > 8000) continue;
      const { packages, customIndex } = parseInstalls(seg.text, seg.prose);
      for (const pkg of packages) {
        const offset = idx.startOf(n) + Math.max(0, lineText.indexOf(pkg.spec));
        if (pkg.action) pkg.action.example = isMarkup && exampleContext;
        out.packages.push({ ...pkg, file, line: lineOverride ?? n, hidden: hiddenAt(offset), excerpt: excerpt(seg.text) });
      }
      if (customIndex) {
        out.findings.push({
          id: 'custom-package-index', severity: 'medium', file, line: lineOverride ?? n, layer,
          why: 'Installs from a non-default package registry, which can serve a different package under a trusted name.',
          excerpt: excerpt(seg.text),
        });
      }
    }
  }

  // Readable text hidden inside base64
  if (depth < 2) {
    for (const m of clean.matchAll(B64_RE)) {
      const buf = Buffer.from(m[0], 'base64');
      if (buf.length < 16) continue;
      let printable = 0;
      for (const byte of buf) if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) printable++;
      if (printable / buf.length < 0.9) continue;
      const decoded = buf.toString('latin1');
      const line = lineAt(m.index);
      const inner = extractText(decoded, { ...ctx, layer: 'base64', depth: depth + 1, lineOverride: line });
      const innerFlags = scanContent(decoded);
      const loaded = inner.urls.length + inner.packages.length + innerFlags.length > 0;
      out.findings.push({
        id: 'encoded-content', severity: loaded ? 'high' : 'medium', file, line, layer,
        why: loaded
          ? 'A base64 blob decodes to readable text that contains links, installs or commands.'
          : 'A base64 blob decodes to readable text. Encoding is a common way to hide content from reviewers.',
        excerpt: excerpt(decoded),
      });
      for (const f of innerFlags) {
        out.findings.push({ id: f.id, severity: f.severity, why: f.why, file, line, layer: 'base64', excerpt: f.samples[0]?.excerpt });
      }
      merge(inner);
    }
  }
  return out;
}

// ---------------------------------------------------------- inventory

const LOCAL_DOWNGRADE = { 'instruction-override': 'medium', concealment: 'low' };
const BASE_BY_USAGE = { execute: 'high', download: 'medium', instruction: 'low', mention: 'info' };
const topUsage = (list) => list.reduce((a, b) => (USAGE_ORDER.indexOf(b) > USAGE_ORDER.indexOf(a) ? b : a), 'mention');

export function assessUrl(ref) {
  const flagMax = maxSeverity(ref.flags.map((f) => f.severity));
  let severity = maxSeverity(BASE_BY_USAGE[ref.usage], flagMax);
  if (ref.usage === 'execute' && rank(flagMax) >= rank('medium')) severity = 'critical';
  if (ref.hidden.length) severity = maxSeverity(bump(severity), 'medium');
  return severity;
}

export function buildInventory(files) {
  const urls = new Map();
  const packages = new Map();
  const findings = [];

  for (const file of files) {
    if (file.kind === 'symlink') {
      findings.push({ id: 'symlink', severity: 'medium', file: file.path, why: `A symbolic link to "${excerpt(file.target, 80)}". Links can pull in files from outside the skill.` });
      continue;
    }
    if (file.kind === 'opaque') {
      findings.push({ id: 'not-inspected', severity: 'low', file: file.path, why: `Not inspected (${file.reason}). Cleat fingerprints this file but cannot read what it does.` });
      continue;
    }
    const isMarkup = /\.(?:md|mdx|markdown|html?)$/i.test(file.path);
    const res = extractText(file.text, { file: file.path, isMarkup });
    for (const f of scanContent(file.text)) {
      // In a skill's own visible text these phrases are often a warning that
      // quotes the attack. They keep full weight in remote and hidden content.
      const quoted = LOCAL_DOWNGRADE[f.id];
      findings.push({
        id: f.id, severity: quoted || f.severity, file: file.path, line: f.samples[0]?.line, count: f.count, excerpt: f.samples[0]?.excerpt,
        why: quoted ? `${f.why} Skills that warn about attacks sometimes quote such phrases, so check which this is.` : f.why,
      });
    }
    findings.push(...res.findings);

    for (const occ of res.urls) {
      let ref = urls.get(occ.url);
      if (!ref) {
        const u = new URL(occ.url);
        ref = {
          id: `url:${occ.url}`, kind: 'url', url: occ.url, host: u.hostname,
          occurrences: [], usage: 'mention', hidden: [], flags: [], immutable: false,
          templated: false, reserved: isReserved(u), schemeless: false, upload: false, secrets: false,
        };
        urls.set(occ.url, ref);
      }
      ref.occurrences.push({ file: occ.file, line: occ.line, usage: occ.usage, hidden: occ.hidden, excerpt: occ.excerpt });
      ref.templated ||= occ.templated;
      ref.schemeless ||= occ.schemeless;
      ref.upload ||= occ.upload;
      ref.secrets ||= Boolean(occ.upload && occ.secrets);
      if (occ.hidden && !ref.hidden.includes(occ.hidden)) ref.hidden.push(occ.hidden);
    }
    for (const occ of res.packages) {
      const key = `${occ.eco}:${occ.name}`;
      let ref = packages.get(key);
      if (!ref) {
        ref = { id: key, kind: 'package', ecosystem: occ.eco, name: occ.name, source: occ.source || 'registry', specs: [], occurrences: [], exec: false, pinned: true, hidden: [] };
        packages.set(key, ref);
      }
      if (!ref.specs.includes(occ.spec)) ref.specs.push(occ.spec);
      ref.occurrences.push({ file: occ.file, line: occ.line, hidden: occ.hidden, excerpt: occ.excerpt });
      if (occ.action) (ref.actions ||= []).push({ ...occ.action, file: occ.file, line: occ.line, excerpt: occ.excerpt });
      ref.exec ||= occ.exec;
      if (occ.pinned !== true) ref.pinned = occ.pinned === null && ref.pinned !== false ? null : false;
      if (occ.hidden && !ref.hidden.includes(occ.hidden)) ref.hidden.push(occ.hidden);
    }
  }

  for (const ref of urls.values()) {
    ref.usage = topUsage(ref.occurrences.map((o) => o.usage));
    const { flags, immutable } = urlFlags(new URL(ref.url), ref);
    ref.flags = flags;
    if (ref.secrets) ref.flags.push({ id: 'receives-secrets', severity: 'high', why: 'The skill sends stored keys, passwords or environment variables to this address in the same command.' });
    else if (ref.upload) ref.flags.push({ id: 'receives-data', severity: 'medium', why: 'The skill sends data to this address. Normal for an API, worth checking for anything else.' });
    ref.immutable = immutable;
    ref.severity = assessUrl(ref);
  }
  for (const ref of packages.values()) {
    ref.usage = ref.exec ? 'execute' : 'download';
    ref.flags = [];
    if (ref.source === 'git') {
      ref.flags.push({ id: 'git-source', severity: ref.pinned ? 'low' : 'medium', why: 'Installed straight from a git repository rather than a package registry.' });
    }
    if (ref.pinned === false) {
      ref.flags.push({
        id: 'unpinned', severity: ref.exec ? 'medium' : 'low',
        why: ref.exec
          ? 'Downloads and runs whatever the newest version is at the time, so a future release can change what happens.'
          : 'No exact version, so a future release can change what gets installed.',
      });
    }
    ref.severity = maxSeverity(ref.flags.map((f) => f.severity));
    if (ref.hidden.length) ref.severity = maxSeverity(bump(ref.severity), 'medium');
  }

  return { urls: [...urls.values()], packages: [...packages.values()], findings };
}

export function skillName(files, fallback) {
  const main = files.find((f) => /^skill\.md$/i.test(f.path) && f.text);
  const fm = main && /^---\r?\n([\s\S]*?)\r?\n---/.exec(main.text);
  const name = fm && /^name:\s*["']?([^"'\r\n]+)/m.exec(fm[1]);
  return (name ? name[1].trim() : fallback).replace(/[^A-Za-z0-9._-]+/g, '-').slice(0, 80) || 'skill';
}
