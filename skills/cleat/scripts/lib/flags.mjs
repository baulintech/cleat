// Red-flag rules for text. Used on the skill's own files and on the remote
// content a skill points to. Rules are line based and bounded so that
// attacker-controlled input cannot make them slow.
import { excerpt, maxSeverity } from './util.mjs';

// A shell always runs what it is fed. An interpreter only does when it reads
// a program from the pipe, not when it is given -m, -c or -e (for example
// "| python -m json.tool" just formats the output).
const SH = '(?:(?:ba|z|da|k|fi)?sh|iex|invoke-expression|(?:python[23]?|node|perl|ruby)(?![ \\t]+-[mce]\\b))';
const DL = '(?:curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)';

export const RULES = [
  {
    id: 'pipe-to-shell',
    severity: 'high',
    why: 'Downloads content and runs it straight away, so whoever controls the source controls the machine.',
    // The downloader must be given something (a URL or variable), which skips
    // prose such as "never run `curl | sh` lines".
    re: new RegExp(`\\b${DL}\\b\\s+[^\\n|\\s][^\\n|]*\\|\\s*(?:sudo\\s+)?${SH}\\b`, 'i'),
  },
  {
    id: 'download-into-shell',
    severity: 'high',
    why: 'Runs the output of a download as shell code.',
    re: /(?:\b(?:(?:ba|z)?sh|source|eval)\b|(?:^|\s)\.)\s+(?:-c\s+)?["']?(?:<\(|\$\()\s*(?:curl|wget)\b/i,
  },
  {
    id: 'powershell-download-run',
    severity: 'high',
    why: 'PowerShell downloads content and executes it.',
    re: /\b(?:iex|invoke-expression)\b[^\n]{0,120}\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|net\.webclient)\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,200}\|\s*(?:iex|invoke-expression)\b/i,
  },
  {
    id: 'decode-and-run',
    severity: 'high',
    why: 'Decodes hidden content and executes it. This is a common way to hide a payload from reviewers.',
    re: new RegExp(
      `\\bbase64\\s+(?:-d|-D|--decode)\\b[^\\n|]*\\|\\s*(?:sudo\\s+)?${SH}\\b|\\beval\\s*\\(\\s*atob\\s*\\(|\\s-(?:enc|encodedcommand)\\s+[A-Za-z0-9+/=]{20,}`,
      'i',
    ),
  },
  {
    id: 'reverse-shell',
    severity: 'high',
    why: 'Opens a remote control channel to another machine.',
    // A bare /dev/tcp probe (a port check) is not a shell: it has to be wired to one.
    re: /\b(?:ba|z)?sh\s+-i\b[^\n]{0,40}\/dev\/(?:tcp|udp)\/|\/dev\/(?:tcp|udp)\/[^\n]{0,80}\b0>&1|\bnc(?:at)?\b[^\n]{0,80}\s-e\s|\bbash\s+-i\s*>&|\bmkfifo\b[^\n]{0,120}\bnc\b|\bsocat\b[^\n]{0,120}\bexec:/i,
  },
  {
    id: 'security-bypass',
    severity: 'high',
    why: 'Switches off a built-in protection (quarantine, antivirus, permission prompts).',
    re: /xattr\s+-[a-z]*d[a-z]*\s+com\.apple\.quarantine|spctl\s+--master-disable|Set-MpPreference\s+-Disable|Add-MpPreference\s+-Exclusion|--dangerously-skip-permissions|\bsetenforce\s+0\b/i,
  },
  {
    id: 'instruction-override',
    severity: 'high',
    why: 'Text that tries to override the instructions the agent already has.',
    re: /\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|guidelines|prompts)|\bdisregard\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above)\s+(?:instructions|rules|guidelines)|\b(?:new|updated|real)\s+system\s+prompt\b|\byou\s+are\s+now\s+(?:in\s+)?(?:developer\s+mode|dan\b|unrestricted|jailbr)/i,
  },
  {
    id: 'concealment',
    severity: 'medium',
    why: 'Tells the agent to hide what it is doing from the person it works for.',
    re: /\b(?:do\s+not|don't|never)\s+(?:tell|inform|notify|alert)\s+(?:the\s+)?(?:user|human|operator)\b(?!\s+to\b)|\bwithout\s+(?:telling|notifying|informing|alerting)\s+(?:the\s+)?(?:user|human|operator)\b|\b(?:silently|secretly|quietly)\s+(?:run|execute|send|upload|install|download|copy|post)\b/i,
  },
  {
    id: 'credential-access',
    severity: 'medium',
    why: 'Touches places where keys, passwords or tokens are stored.',
    re: /~?\/?\.ssh\/|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws\/credentials|\.git-credentials|\.netrc\b|\.npmrc\b|\.kube\/config|\.docker\/config\.json|\.config\/gcloud|find-generic-password|login\.keychain|wallet\.dat|\/etc\/shadow|\bLogin Data\b/i,
  },
  {
    id: 'env-harvest',
    severity: 'medium',
    why: 'Collects environment variables, which usually hold API keys.',
    // env must be a command (not "<env>" or "Env>"), with its output piped or saved.
    re: /(?:^|[\s;&(])(?:printenv|env)\s*(?:\|(?!\|)|>\s*[\w/~.$"'])|\bprocess\.env\b[^\n]{0,80}\b(?:fetch|axios|request|post)\s*\(|\bos\.environ\b[^\n]{0,80}\b(?:requests|urllib|post)\b/i,
  },
  {
    id: 'data-upload',
    severity: 'medium',
    why: 'Sends local data to a remote server.',
    // Case matters: curl -d and -F upload, but -D (save headers) and -f do not.
    re: /\bcurl\b[^\n|]{0,400}\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file)[\s=]|\bwget\b[^\n]{0,400}--post-(?:data|file)|\b[Ii]nvoke-(?:[Ww]eb[Rr]equest|[Rr]est[Mm]ethod)\b[^\n]{0,400}-[Mm]ethod\s+["']?[Pp][Oo][Ss][Tt]/,
  },
  {
    id: 'persistence',
    severity: 'medium',
    why: 'Sets something up to keep running after the task ends.',
    re: /\bcrontab\b|Launch(?:Agents|Daemons)|\blaunchctl\s+load\b|\bsystemctl\s+enable\b|\bschtasks\b|CurrentVersion\\+Run\b|>>\s*\S*\.(?:bashrc|zshrc|profile|bash_profile)\b|authorized_keys/i,
  },
  {
    id: 'agent-config-tampering',
    severity: 'medium',
    why: 'Changes the standing instructions or settings of the agent itself, which outlives this task.',
    re: /\b(?:write|append|add|insert|modify|edit|update|overwrite|replace)\b[^\n]{0,80}(?:CLAUDE\.md|AGENTS\.md|MEMORY\.md|\.claude\/settings(?:\.local)?\.json|\.mcp\.json|\.cursorrules|\.cursor\/rules)/i,
  },
  {
    id: 'protected-archive',
    severity: 'medium',
    why: 'Password-protected archives stop security tools from inspecting what is inside.',
    re: /\bunzip\s+-P\b|\b7za?\s+x\b[^\n]{0,120}\s-p\S|\b(?:archive|zip)\s+password\b/i,
  },
  {
    id: 'wallet-or-seed',
    severity: 'medium',
    why: 'Mentions cryptocurrency wallet secrets.',
    re: /\bseed\s+phrase\b|\bmnemonic\s+phrase\b|\bmetamask\b[^\n]{0,40}\b(?:vault|key|export)/i,
  },
];

const MAX_LINE = 8000;
const SAMPLES = 3;

// Returns [{ id, severity, why, count, samples: [{ line, excerpt }] }].
export function scanContent(text) {
  const found = new Map();
  let longLines = 0;
  const lines = text.split('\n');
  let group = '';
  let groupStart = 0;
  const flush = () => {
    if (!group) return;
    let body = group;
    if (body.length > MAX_LINE) {
      longLines++;
      body = body.slice(0, MAX_LINE);
    }
    for (const rule of RULES) {
      if (!rule.re.test(body)) continue;
      let hit = found.get(rule.id);
      if (!hit) {
        hit = { id: rule.id, severity: rule.severity, why: rule.why, count: 0, samples: [] };
        found.set(rule.id, hit);
      }
      hit.count++;
      if (hit.samples.length < SAMPLES) {
        hit.samples.push({ line: groupStart, excerpt: excerpt(body) });
      }
    }
    group = '';
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/\r$/, '');
    if (!group) groupStart = i + 1;
    if (/\\\s*$/.test(line) && group.length < MAX_LINE) {
      group += line.replace(/\\\s*$/, ' ');
      continue;
    }
    group += line;
    flush();
  }
  flush();

  const ids = new Set(found.keys());
  const sends = ids.has('data-upload') || ids.has('reverse-shell') || ids.has('pipe-to-shell');
  if ((ids.has('credential-access') || ids.has('env-harvest')) && sends) {
    found.set('possible-exfiltration', {
      id: 'possible-exfiltration',
      severity: 'high',
      why: 'Reads secrets and also sends data out or runs remote code in the same file.',
      count: 1,
      samples: [],
    });
  }
  if (longLines > 0) {
    found.set('long-lines', {
      id: 'long-lines',
      severity: 'low',
      why: `${longLines} very long line(s) were only inspected up to ${MAX_LINE} characters.`,
      count: longLines,
      samples: [],
    });
  }
  return [...found.values()];
}

export const worstOf = (findings) => maxSeverity(findings.map((f) => f.severity));
