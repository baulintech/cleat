// The Cleat banner. Shown only to a person at a terminal: never to an agent,
// a pipe, a CI log or JSON output, so it costs them nothing to read past.

const ART = [
  ' ██████╗██╗     ███████╗ █████╗ ████████╗',
  '██╔════╝██║     ██╔════╝██╔══██╗╚══██╔══╝',
  '██║     ██║     █████╗  ███████║   ██║',
  '██║     ██║     ██╔══╝  ██╔══██║   ██║',
  '╚██████╗███████╗███████╗██║  ██║   ██║',
  ' ╚═════╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝',
];

const TAGLINE = 'Know what your skills reach for. Notice when it moves.';

export function shouldShowBanner({ json = false, env = process.env, stdout = process.stdout, stderr = process.stderr } = {}) {
  if (json) return false;
  if (env.CLEAT_NO_BANNER || env.CI) return false;
  return Boolean(stdout.isTTY && stderr.isTTY);
}

export function renderBanner(version, { env = process.env } = {}) {
  const colour = !env.NO_COLOR && env.TERM !== 'dumb';
  const orange = (s) => (colour ? `\x1b[38;2;245;134;52m${s}\x1b[0m` : s);
  const dim = (s) => (colour ? `\x1b[2m${s}\x1b[0m` : s);
  return `\n${ART.map(orange).join('\n')}\n  ${dim(`${TAGLINE}  v${version}`)}\n\n`;
}
