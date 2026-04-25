# Security Policy

## Supported Versions

Security fixes are applied to the latest released version of
**vintage-gateway**.  Older versions do not receive patches; please
upgrade before reporting.

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅         |
| < 0.3   | ❌         |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security problems.**

Instead, choose one of:

1. **GitHub Security Advisories (preferred).**  Open a private report
   at
   [github.com/rickybryce/vintage-gateway/security/advisories/new](https://github.com/rickybryce/vintage-gateway/security/advisories/new).
   This keeps the details confidential until a fix is ready.
2. **Email.**  Send a description to `rbryce@nevco.com` with the subject
   line `vintage-gateway security`.  If the issue is sensitive, you may
   encrypt the body with my public GPG key — the fingerprint is
   published in the signed release artifacts (see
   [README → Verifying Releases](README.md#verifying-releases)).

Please include:

- A clear description of the issue.
- Steps to reproduce or a proof-of-concept.
- The version and target platform you observed it on.
- Any suggested mitigation or patch, if you have one.

## What to Expect

- **Acknowledgement** within 7 days that the report has been received.
- **Triage** within 14 days with an initial assessment (severity,
  reproducibility, affected versions).
- **Fix timeline** communicated after triage.  Critical issues are
  typically resolved in a patch release within 30 days; lower-severity
  items roll into the next scheduled release.
- **Public disclosure** coordinated with the reporter.  The default is
  to publish a GitHub Security Advisory (with a CVE when appropriate)
  once a fixed version is available, crediting the reporter unless
  they request anonymity.

## Scope

In scope:

- The vintage-gateway binary itself.
- Protocol handling (telnet, SSH, XMODEM, Hayes AT emulator).
- Configuration parsing and on-disk credential storage.
- Build scripts and release artifacts.

Out of scope:

- Vulnerabilities in upstream dependencies — please report those to the
  upstream project.  If the dependency's advisory warrants a patched
  version of vintage-gateway, file it here as "upgrade X to Y" and I'll
  ship a release.
- Attacks that require physical access to the server machine.
- Social-engineering the operator into accepting a bad host key (the
  gateway logs such decisions to support forensic review, but cannot
  prevent them).

## Security Model Snapshot

- **Sensitive files** (`vgateway.conf`, `dialup.conf`, `gateway_hosts`,
  `vintage_ssh_host_key`, `vintage_gateway_ssh_key`) are written with
  mode `0o600` on Unix.  Windows users should place the binary in a
  per-user folder for equivalent NTFS ACL protection.
- **Credential comparison** is constant-time on both telnet and SSH.
- **Brute-force lockout** is shared across telnet and SSH: 3 failed
  attempts in 5 minutes → 5-minute lockout for that IP, across both
  protocols.
- **SSH host keys** from remote servers are verified against a local
  TOFU store (`gateway_hosts`).  All trust decisions (first-time
  accept, key update, key reject) are written to the server log.
- **Telnet gateway SB-body** is capped at 8 KiB to prevent a
  malicious remote from exhausting memory.

See [README.md](README.md#warning) for the deployment warning and
[the Standards Compliance section](README.md#standards-compliance)
for the full RFC footprint.
