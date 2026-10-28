# Changelog

All notable changes to `prism-secret-scan` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-10-28

A correctness release. Every item below was found by auditing the 1.0.0 source, and each
one has a regression test in `test/secretscan.test.js`.

### Fixed

- **Keys hidden by terminal colour codes were missed.** A token pasted inside ANSI
  escape sequences (`\x1b[31mghp_…\x1b[0m`) produced no finding at all. ANSI sequences
  are now stripped before matching.
- **A leading BOM hid the first line of a file.** Files saved by some Windows editors
  start with `\uFEFF`; the token on that line was never detected. The BOM is stripped.
- **A placeholder word anywhere on the line silenced a real key.** The fake-secret
  filter used to test the whole line, so `const sample = 1, t = "ghp_…"` reported
  nothing. The filter now tests the matched secret only.
- **`--history` ignored `.secretscanignore`, `.gitignore` and `--exclude`.** Rules you
  wrote were silently dropped in history mode. All three are now honoured, using the
  same matcher as a directory scan.
- **Baseline entries were location-bound.** `--baseline` fingerprints a secret by value,
  so the same key on a different line — or in a different commit — is now correctly
  treated as already accepted instead of being reported again.
- **Files over 2 MB disappeared without a word.** They are now listed as skipped, with
  their size and the limit that was applied.
- **`--history` outside a git repository** now fails with `Not a git repository —
  --history needs a repo` instead of leaking a raw `execFileSync` stack trace.

### Added

- `CHANGELOG.md` (this file).
- Regression tests for all of the above (5 → 13 tests).
- `skippedLarge` / `skippedBinary` counts returned from `scanDir()` for programmatic use.
- `isIgnored()` and `loadIgnoreRules()` exported from `src/index.js`.

### Changed

- Rule regexes are reset (`lastIndex = 0`) before each match, so a future global or
  sticky flag on any rule cannot leak state between lines.
- Lines are trimmed of a trailing `\r`, so CRLF files behave exactly like LF files.

## [1.0.0] — 2026-10-26

First public release.

- 28 detectors across AI, cloud, payments, messaging and database providers.
- Entropy + placeholder filtering for generic hardcoded secrets.
- `--history` scans every commit on every branch, reporting commit, author and date.
- Masked output by default, `--show` to reveal.
- `--baseline`, `.secretscanignore`, inline `secretscan:ignore`.
- `--sarif` for GitHub code scanning, `--json`, `--severity`. Exit code 1 on findings.
- Zero dependencies, Node.js 18.17+.
