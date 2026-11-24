# Contributing to Cleat

Thanks for looking. Cleat is small and young, so a focused contribution makes
a real difference.

## Good places to start

Look for issues labelled
[good first issue](https://github.com/baulintech/cleat/labels/good%20first%20issue)
or [help wanted](https://github.com/baulintech/cleat/labels/help%20wanted).
Useful kinds of help:

- **Test cases from real skills.** A skill that Cleat misreads, or one it
  should flag and does not. Even an issue with a link and a short description
  helps.
- **Detection rules.** New red-flag patterns live in
  `skills/cleat/scripts/lib/flags.mjs`. Each rule needs a test showing what it
  catches and one showing what it must not catch.
- **Fewer false alarms.** Content is normalised before hashing in
  `skills/cleat/scripts/lib/safefetch.mjs` (`normaliseText`).
- **Ways to run Cleat**, such as a GitHub Action.

## Ground rules

1. **No runtime dependencies.** Cleat uses the Node.js standard library only.
   A supply-chain tool should not bring a package tree of its own. Please
   discuss in an issue first if you think something truly needs one.
2. **Every change comes with a test.** Bug fixes get a test that fails before
   the fix.
3. **Cleat never runs what it scans.** It reads and fingerprints content. Keep
   it that way, and keep all network access going through `safeFetch`.
4. **Fixtures stay fake.** Test skills must not point at real hosts. Use the
   fake network (`fakeNet`) in `test/cleat.test.mjs`, as the existing tests do.

## Running the tests

Node 18 or newer, nothing else:

```bash
node --test
```

The tests run offline. Continuous integration runs them on Linux, macOS and
Windows with Node 18, 20 and 22.

## Reporting a security problem

Please do not open a public issue for a vulnerability in Cleat itself. See
[SECURITY.md](SECURITY.md).

## Licence

By contributing you agree that your contribution is released under the
[MIT licence](LICENSE).
