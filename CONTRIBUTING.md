# Contributing to gtv-triage

Thanks for helping harden the toolkit! 🚧 This project is **work in progress**,
so contributions — especially fresh IOCs and YARA tuning — are very welcome.

## Ground rules

- **Authorized use only.** This is a defensive tool for assessing devices you own
  or have explicit permission to test. Don't submit offensive tooling, exploit
  payloads, or anything designed to evade detection for malicious ends.
- **No real victim data.** Never include device serials, IPs, personal app lists,
  or other PII from a real scan in a PR, issue, or test fixture. Sanitize first.
- **Cite your sources.** New indicators must come with a public reference
  (vendor report, CERT advisory, reputable threat-intel writeup).

## Ways to contribute

### 🦠 Add or refresh IOCs (`gtv-iocs.txt`)
- One indicator per line; `#` starts a comment. Keep entries **specific** —
  matching is a case-insensitive substring, so short/generic tokens (e.g. a bare
  `wd`) must be given as a full path instead to avoid false positives.
- Group under the right family header and add a source comment.
- Note the compile date when you refresh — C2 infrastructure rotates fast.

### 🧬 Add or tune YARA rules (`gtv-malware.yar`)
- No external modules — rules must compile with stock `yara`/`yara-x` everywhere.
- **Guard against public blocklists.** Domain-based rules must keep the
  `StevenBlack` / `0.0.0.0 ` hosts-file guard so bundled ad/malware blocklists
  (which *list* bad domains to block them) don't trigger a match. See the existing
  rules for the pattern.
- Add a `meta:` block with `description`, `family`, `reference`, and `date`.
- **Test both directions:** include a positive sample string that should match and
  confirm a benign file (e.g. a hosts blocklist) does **not** match.

### 🐍 Code changes (`gtv-triage.py`)
- Python 3.8+, **standard library only** — no third-party dependencies.
- Keep the non-root constraint: everything must work over plain ADB without root.
- Preserve the `raw/` → `norm/` → `summary.txt` → `diff.txt` run layout.
- Scoring changes: keep it **severity-gated** (a device with zero CRITICAL/HIGH
  findings must never read as "compromised"). Explain any weight changes in the PR.

## Before you open a PR

Run the same checks CI runs:

```bash
# Python compiles clean
python3 -m py_compile gtv-triage.py

# YARA rules compile
yara gtv-malware.yar /dev/null

# (optional) regression: positive sample matches, blocklist does not
printf '/system/xbin/vo1d\nmeiboot.com\n' > /tmp/pos.txt
yara gtv-malware.yar /tmp/pos.txt      # expect: AndroidTV_Vo1d_Backdoor
```

Then:

1. Fork, branch (`git checkout -b add-xyz-iocs`).
2. Make focused changes with a clear commit message.
3. Open a PR describing **what** changed and **the source** behind it.

## Reporting issues

Found a false positive, a missed family, or a bug? Open an issue with:
- The device model / Android version (no serials or IPs).
- The rule or indicator involved.
- The expected vs. actual behavior, and a sanitized snippet if possible.

Thanks again — every verified indicator makes the next person's living room safer. 📺🛡️
