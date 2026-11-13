// Read-only fetcher for attacker-controlled URLs.
//
// Guarantees:
//  - http and https only, GET only, no cookies, no credentials in the URL
//  - the address is checked at connect time (inside the DNS lookup), so a
//    name that resolves to a private, loopback, link-local or metadata
//    address is refused, including after a redirect or a DNS rebind
//  - redirects are followed by hand, each hop re-validated, with a hop limit
//  - the body is capped in size and time, never decompressed, never written
//    to disk by this module, and never executed
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import net from 'node:net';
import { sha256, VERSION } from './util.mjs';

const blocked = new net.BlockList();
for (const [addr, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
]) blocked.addSubnet(addr, prefix, 'ipv4');
for (const [addr, prefix] of [
  ['::', 96],          // unspecified, loopback, IPv4-compatible
  ['64:ff9b::', 96],   // NAT64
  ['100::', 64],       // discard
  ['2001::', 32],      // Teredo
  ['2001:db8::', 32],  // documentation
  ['2002::', 16],      // 6to4
  ['fc00::', 7],       // unique local
  ['fe80::', 10],      // link local
  ['ff00::', 8],       // multicast
]) blocked.addSubnet(addr, prefix, 'ipv6');

export function isPublicAddress(address) {
  let addr = String(address).trim();
  if (addr.startsWith('[') && addr.endsWith(']')) addr = addr.slice(1, -1);
  addr = addr.replace(/%.*$/, '');
  const family = net.isIP(addr);
  if (family === 4) return !blocked.check(addr, 'ipv4');
  if (family === 6) {
    // Any IPv6 form that embeds an IPv4 address is refused outright.
    if (/^::ffff:/i.test(addr) || /\d+\.\d+\.\d+\.\d+$/.test(addr)) return false;
    return !blocked.check(addr, 'ipv6');
  }
  return false;
}

const BLOCKED_NAMES = /^(?:localhost|.*\.localhost|.*\.local|.*\.internal|.*\.lan|.*\.home\.arpa)$/i;

// Returns a reason string when the URL must not be requested, else null.
export function refuseReason(url, allow = isPublicAddress) {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return `scheme ${url.protocol} not allowed`;
  if (url.username || url.password) return 'credentials in URL';
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!host) return 'empty host';
  if (net.isIP(host)) return allow(host) ? null : `address ${host} is not public`;
  if (BLOCKED_NAMES.test(host) && allow === isPublicAddress) return `host ${host} is local`;
  if (!host.includes('.')) return allow === isPublicAddress ? `host ${host} is not a public name` : null;
  return null;
}

const DEFAULT_UA = `cleat/${VERSION} (read-only reference check)`;

function requestOnce(url, { maxBytes, timeoutMs, userAgent, allow }) {
  return new Promise((resolve, reject) => {
    let done = false;
    const settle = (fn, value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      fn(value);
    };
    const lookup = (hostname, options, callback) => {
      if (typeof options === 'function') { callback = options; options = {}; }
      dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
        if (err) return callback(err);
        const bad = addresses.find((a) => !allow(a.address));
        if (bad) {
          const e = new Error(`${hostname} resolves to non-public address ${bad.address}`);
          e.code = 'ECLEAT_BLOCKED';
          return callback(e);
        }
        if (options.all) return callback(null, addresses);
        return callback(null, addresses[0].address, addresses[0].family);
      });
    };
    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.request(
      url,
      {
        method: 'GET',
        lookup,
        agent: false,
        headers: {
          'user-agent': userAgent,
          accept: 'text/*, application/json;q=0.9, */*;q=0.5',
          'accept-encoding': 'identity',
        },
      },
      (res) => {
        const status = res.statusCode || 0;
        const location = res.headers.location;
        if ([301, 302, 303, 307, 308].includes(status) && location) {
          res.resume();
          settle(resolve, { status, location });
          req.destroy();
          return;
        }
        const chunks = [];
        let bytes = 0;
        let truncated = false;
        const finish = () =>
          settle(resolve, {
            status,
            contentType: String(res.headers['content-type'] || '').slice(0, 200),
            body: Buffer.concat(chunks),
            truncated,
          });
        res.on('data', (chunk) => {
          if (bytes + chunk.length > maxBytes) {
            chunks.push(chunk.subarray(0, maxBytes - bytes));
            bytes = maxBytes;
            truncated = true;
            finish();
            req.destroy();
          } else {
            chunks.push(chunk);
            bytes += chunk.length;
          }
        });
        res.on('end', finish);
        res.on('error', (err) => settle(reject, err));
      },
    );
    const timer = setTimeout(() => {
      const e = new Error('timed out');
      e.code = 'ETIMEDOUT';
      settle(reject, e);
      req.destroy();
    }, timeoutMs);
    req.on('error', (err) => settle(reject, err));
    req.end();
  });
}

const isTextBuffer = (buf) => !buf.subarray(0, 8000).includes(0);

// Linear-time removal of <tag>...</tag> blocks. Regexes are avoided here
// because the input is hostile and can be shaped to make them slow.
function dropBlocks(text, open, close) {
  const lower = text.toLowerCase();
  let out = '';
  let pos = 0;
  for (;;) {
    const start = lower.indexOf(open, pos);
    if (start === -1) return out + text.slice(pos);
    out += text.slice(pos, start) + ' ';
    const end = lower.indexOf(close, start + open.length);
    if (end === -1) return out;
    const gt = lower.indexOf('>', end);
    if (gt === -1) return out;
    pos = gt + 1;
  }
}

function stripTags(text) {
  let out = '';
  let pos = 0;
  for (;;) {
    const lt = text.indexOf('<', pos);
    if (lt === -1) return out + text.slice(pos);
    out += text.slice(pos, lt);
    // Keep the text inside HTML comments: agents that read raw HTML see it.
    if (text.startsWith('<!--', lt)) {
      const end = text.indexOf('-->', lt + 4);
      if (end === -1) return out + ' ' + text.slice(lt + 4);
      out += ' ' + text.slice(lt + 4, end) + ' ';
      pos = end + 3;
      continue;
    }
    const gt = text.indexOf('>', lt);
    if (gt === -1) return out + text.slice(lt);
    out += ' ';
    pos = gt + 1;
  }
}

const ENTITIES = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&nbsp;': ' ' };

// A stable text form used for hashing and diffing, so that markup noise does
// not look like a content change.
export function normaliseText(text, contentType = '') {
  let t = text.replace(/\r\n?/g, '\n');
  const looksHtml = /html/i.test(contentType) || /^\s*(?:<!doctype html|<html[\s>])/i.test(t.slice(0, 500));
  if (looksHtml) {
    t = dropBlocks(t, '<script', '</script');
    t = dropBlocks(t, '<style', '</style');
    t = stripTags(t);
    t = t.replace(/&(?:amp|lt|gt|quot|#39|nbsp);/g, (m) => ENTITIES[m]);
  }
  return t
    .split('\n')
    .map((line) => line.replace(/[ \t\u00a0]+/g, ' ').trim())
    .filter(Boolean)
    .join('\n');
}

// Fetch a URL safely. Never throws. Result:
//   { ok, status, finalUrl, redirects, contentType, bytes, truncated,
//     sha256, isText, text, normSha256, error }
export async function safeFetch(rawUrl, opts = {}) {
  const {
    maxBytes = 1024 * 1024,
    timeoutMs = 15000,
    maxRedirects = 5,
    userAgent = DEFAULT_UA,
    _allow = isPublicAddress, // tests only: lets the suite talk to 127.0.0.1
  } = opts;
  const redirects = [];
  let current;
  try {
    current = new URL(rawUrl);
  } catch {
    return { ok: false, error: 'invalid URL', finalUrl: String(rawUrl), redirects };
  }
  const deadline = Date.now() + timeoutMs;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const refused = refuseReason(current, _allow);
    if (refused) return { ok: false, error: `refused: ${refused}`, finalUrl: current.href, redirects };
    let res;
    try {
      res = await requestOnce(current, {
        maxBytes,
        timeoutMs: Math.max(1, deadline - Date.now()),
        userAgent,
        allow: _allow,
      });
    } catch (err) {
      const kind = err.code === 'ECLEAT_BLOCKED' ? `refused: ${err.message}` : `network: ${err.code || err.message}`;
      return { ok: false, error: kind, finalUrl: current.href, redirects };
    }
    if (res.location) {
      let next;
      try {
        next = new URL(res.location, current);
      } catch {
        return { ok: false, error: 'invalid redirect target', finalUrl: current.href, redirects };
      }
      redirects.push({ from: current.href, to: next.href, status: res.status });
      current = next;
      continue;
    }
    const isText = isTextBuffer(res.body);
    const text = isText ? res.body.toString('utf8') : null;
    return {
      ok: res.status >= 200 && res.status < 300,
      status: res.status,
      finalUrl: current.href,
      redirects,
      contentType: res.contentType,
      bytes: res.body.length,
      truncated: res.truncated,
      sha256: sha256(res.body),
      isText,
      text,
      normSha256: isText ? sha256(normaliseText(text, res.contentType)) : sha256(res.body),
      error: res.status >= 200 && res.status < 300 ? null : `HTTP ${res.status}`,
    };
  }
  return { ok: false, error: 'too many redirects', finalUrl: current.href, redirects };
}
