# Changelog

All notable changes to **xmodem-gateway** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_No unreleased changes._

## [0.3.5] - 2026-04-23

### Added

#### ZMODEM protocol support
- **Full ZMODEM send and receive** implemented per the Forsberg 1988
  specification in `src/zmodem.rs` — ZDLE escape layer, hex / binary16 /
  binary32 headers, CRC-16 and CRC-32, batch transfer per §4, receiver
  `ZSKIP` to decline individual files per §7, and `rz\r` auto-start
  trigger so Qodem, ZOC, and other auto-detecting terminals begin the
  transfer without a separate `rz` command.
- **File transfer menu entry** for ZMODEM alongside XMODEM / XMODEM-1K /
  YMODEM. Stop-and-wait flow control (ZCRCQ mid-frame + ZCRCE
  end-of-frame); our `ZRINIT` advertises `CANFDX|CANOVIO|CANFC32` without
  requiring streaming.
- **Additional file-transfer configuration options** surfaced in the
  Gateway Configuration menu.

### Fixed

- **Windows CI**: ZMODEM fixture binaries are now marked as binary in
  `.gitattributes` so the CRLF auto-conversion on Windows runners does
  not corrupt them. Fixes the sporadic Windows CI failure on
  `test_lrzsz_rz_zskip_interop` and the captured-wire replay tests.
- **CI runner configuration**: resolved transient runner errors that
  were preventing reliable green builds.
- **GUI**: copy/paste now works as expected in the configuration editor
  text fields.

### Documentation

- README updated with NULL-modem adapter guidance and a clarified telnet
  command example.
- User manual extended with ZMODEM coverage alongside the existing
  XMODEM / YMODEM sections.

### Tests

- **+46 tests** added for the ZMODEM implementation (CRC vectors, ZDLE
  round-trips, header round-trips, subpacket round-trips, ZFILE parser,
  full send↔receive round-trips, batch / skip handling, ZABORT, non-zero
  `ZRPOS` resume, proptest fuzzers on adversarial bytes) plus two
  `#[ignore]` lrzsz subprocess interop tests. Total: **617** unit +
  proptest tests, all green.

## [0.3.4] - 2026-04-18

### Fixed

#### XMODEM / YMODEM over telnet — full RFC 854 NVT compliance
- **CR-NUL stuffing on both send and receive.** Bare `0x0D` (CR) in file data
  is now emitted on the wire as `CR NUL` per RFC 854 §2.2, and the receive
  path strips trailing `NUL` after `CR`. Without this, any block containing
  a `0x0D` data byte (common in binary files — EXE, PDF, compressed
  archives) desynced the stream by one byte per CR. Visible symptom was
  "Transfer stalls at 3–4 blocks, client repeatedly sends `'C'`".
- **IAC escape/unescape on both directions** matches the existing telnet
  NVT rule already applied to `IAC` itself; the two transforms are now
  always active together when `xmodem_iac` is on.
- **YMODEM end-of-batch handshake on receive.** After ACKing the final
  `EOT`, the server now sends `'C'` and consumes the "null block 0"
  (filename starts with `NUL`) that strict senders emit per Forsberg §7.4.
  Fixes "YMODEM upload completes all data but client hangs" on ExtraPuTTY,
  Tera Term, and lrzsz's `sb`.
- **YMODEM size-based truncation.** After a YMODEM transfer the receiver
  now truncates to the exact `size` field from block 0 instead of stripping
  trailing `SUB` (0x1A) padding. Fixes files that legitimately end in
  `0x1A` bytes (EXEs, some archives) being silently truncated.

### Added

#### Session-side configuration
- **Gateway Configuration menu** at `Configuration → G` in the telnet
  session: toggles the outbound Telnet mode (Telnet / Raw TCP) and the
  outbound SSH auth mode (Key / Password) at runtime, persists to
  `xmodem.conf`, and takes effect on the next gateway connection with no
  server restart. Replaces the per-connection interactive prompts that
  used to live inside the Telnet Gateway and SSH Gateway flows.
- **Config key `ssh_gateway_auth`** (`"key"` or `"password"`, default
  `"password"`) drives the SSH Gateway auth choice. No silent fallback —
  failures now clearly point the user at Server → More or Config → G.
- **Pre-transfer overwrite prompt.** On upload, if the target filename is
  already present the server asks `Overwrite? (Y/N)` *before* the transfer
  starts. Avoids running a multi-MB transfer only to fail at the final
  write step.

#### GUI console
- **"More..." popups** on the Server and Serial Modem frames expose the
  full set of persistent settings that didn't fit on the main panel —
  telnet gateway mode + negotiation, SSH gateway auth (with the gateway's
  public key shown read-only when Key mode is selected), the extended
  Hayes AT profile (E/V/Q, X-level, &C/&D/&K), all 27 S-registers, and
  the four stored phone-number slots. Each popup has its own **Save**
  button that persists without restarting the server.
- **Popup styling** distinct from main panels — deep forest-green panel
  background, brighter-green text-entry fields — so the user immediately
  sees which surface they're editing.

### Changed

#### XMODEM transforms auto-default
- **Default now picked from detected terminal type.** After terminal
  detection, `xmodem_iac` is auto-set to **on** for ANSI sessions
  (PuTTY / ExtraPuTTY, Tera Term, C-Kermit, SecureCRT — all escape per
  RFC) and **off** for PETSCII and ASCII sessions (retro clients like
  IMP8, CCGMS, StrikeTerm, AltairDuino firmware that speak raw bytes
  despite the port-23 connection). User can still flip per-session with
  the `I` key in the File Transfer menu.

#### UX polish
- **Post-transfer settle window.** Error messages after a failed upload
  (transfer failure, save I/O error, duplicate filename) now honour the
  same 1-second pause the success path already used, so ExtraPuTTY's
  transfer dialog has time to close before our message prints. Also
  drains stray bytes from the client's post-transfer chatter so
  `wait_for_key` actually waits for a human keypress.
- **Select Protocol menu** on download now clears the screen instead of
  appending after the download list.
- **Default `ssh_gateway_auth` flipped from `key` to `password`** — works
  out of the box with any SSH server that allows password auth; Key mode
  requires a one-time `authorized_keys` setup.

### Removed

- The interactive `T`-toggle prompt inside the Telnet Gateway flow and
  the `K`-show-pubkey prompt inside the SSH Gateway flow. Both options
  now live in config (editable via GUI Server → More or Config → G).

### Documentation

- User manual §8.3, §8.6 rewritten to reflect NVT symmetry, the auto-IAC
  default, and the overwrite prompt. `index.html` brought in line.
- Modem Emulator help in-session now lists `AT&Zn=s` / `ATDSn` /
  `ATIn` / `ATXn` / `AT&C/&D/&K` / `A/` alongside the pre-existing
  quick reference.

### Tests

- +1 regression test: `test_ymodem_round_trip_preserves_trailing_sub_bytes`
  verifies YMODEM size-truncation preserves a payload that legitimately
  ends in `0x1A` bytes. Total: **571** unit + proptest tests, all green.

## [0.3.3] - 2026-04-18

### Added

#### Telnet server — additional RFC compliance
- **RFC 854 EC / EL**: `IAC EC` now surfaces to line-editors as `DEL` (0x7F)
  and `IAC EL` as `NAK` (0x15), with the `read_input_loop` handling NAK as
  "erase the current line."
- **RFC 859 STATUS** (option 5): `DO STATUS` is answered with `WILL STATUS`;
  `SB STATUS SEND` returns an `SB STATUS IS <state>` dump of every option
  advertised and not yet denied. Works with the Unix `telnet` client's
  `status` / `send status` subcommands.
- **RFC 860 TIMING-MARK** (option 6): `DO TIMING-MARK` is answered with
  `WILL TIMING-MARK` after flushing pending output, providing clients a
  processing-synchronization point.

#### Outgoing Telnet Gateway
- **IAC escape/unescape** in both directions; literal 0xFF data bytes now
  survive the wire without being mistaken for IAC.
- **Full RFC 1143 six-state Q-method** (`No`, `Yes`, `WantYes`,
  `WantYesOpposite`, `WantNo`, `WantNoOpposite`) for option negotiation.
- **Cooperative mode** (`telnet_gateway_negotiate = true`): proactively
  offers `WILL TTYPE`, `WILL NAWS`, and `DO ECHO` at connect; responds to
  `SB TTYPE SEND` with the local user's terminal type; responds to
  `DO NAWS` with the local user's current window size; forwards NAWS
  updates mid-session when the local user resizes.
- **Raw-TCP escape hatch** (`telnet_gateway_raw = true`): bypasses the
  telnet IAC layer entirely for destinations that aren't really telnet.
  Toggleable live from the Telnet Gateway menu with the **T** key; choice
  persists to `xmodem.conf`.
- **8 KiB subnegotiation body cap**: malicious remotes cannot exhaust
  memory by sending huge `SB` bodies without a terminating `IAC SE`.
- **Property-based fuzz test** (`qmethod_proptest`) covers the full Q-method
  state machine with randomized sequences. Regression corpus checked into
  `proptest-regressions/telnet.txt`.

#### Outgoing SSH Gateway
- **Public-key authentication** with auto-generated Ed25519 client keypair
  (`xmodem_gateway_ssh_key`, 0o600 on Unix). Tried before password; on
  acceptance, the password prompt is skipped entirely.
- **"Show gateway public key" menu**: press **K** at the SSH Gateway
  menu to display the one-line OpenSSH-format public key for pasting
  into a remote's `~/.ssh/authorized_keys`.
- **Audit log for host-key trust decisions**: TOFU-accept, key-update,
  and key-reject events are written to `glog!` with host, port,
  algorithm, and SHA-256 fingerprint.

#### Hayes modem emulator
- **`A/` repeat-last-command** (no `AT` prefix, no CR required).
- **`ATI0`–`ATI7`** identification variants (product code, ROM checksum,
  ROM test, firmware, OEM, country, diagnostics, product info).
- **Stored phone-number slots**: `AT&Zn=s` stores a number in slot
  `n ∈ {0,1,2,3}`; `ATDS` / `ATDS<n>` dials it. Persisted by `AT&W`,
  restored by `ATZ`. Preserves hostname case so `AT&Z1=Pine.Example.com`
  works.
- **S-registers expanded to S0–S26**: S13–S24 are reserved-zero
  placeholders for legacy init strings; S25 (DTR detect time) and
  S26 (RTS/CTS delay) match Hayes defaults.
- **Dial-string modifiers**: `,` (pause by S8), `W` (wait-for-dialtone by
  S6), `;` (stay in command mode), `*`/`#` (preserved DTMF digits),
  `P`/`T`/`@`/`!` (accepted, ignored). Hostname heuristic prevents
  stripping `P`/`T`/`W` from names like `pine.example.com`.
- **ATX0–ATX4** result-code verbosity per RFC.
- **`AT&C` / `AT&D` / `AT&K`**: parsed, stored, persisted, displayed in
  `AT&V`. Actual hardware pins are not driven; see README limitations.
- **Silent-OK fallback** for unknown commands (`ATB`, `ATC`, `ATL`,
  `ATM`, `AT&B`, `AT&G`, `AT&J`, `AT&S`, `AT&T`, `AT&Y`, …) so legacy
  init strings don't halt mid-setup.

### Security

- **Shared per-IP brute-force lockout** across telnet and SSH servers.
  After 3 failed authentication attempts in 5 minutes, the source IP is
  blocked for 5 minutes across both protocols — an attacker can't bounce
  between them to reset the counter.
- **0o600 file permissions on Unix** for all sensitive files:
  `xmodem.conf`, `dialup.conf`, `gateway_hosts`, `xmodem_ssh_host_key`,
  `xmodem_gateway_ssh_key`.
- **Per-PID temporary filenames** for atomic config writes; closes a
  TOCTOU window on shared working directories.
- **`save_config` now acquires the `CONFIG` mutex before disk write**,
  so a concurrent session-side `update_config_values` can't clobber the
  GUI-initiated write.
- **SSH Gateway** now calls `session.disconnect` on every early-return
  path after authentication, preventing orphaned authenticated sessions
  on the remote.

### Fixed

- Q-method refusal flags (`sent_dont` / `sent_wont`) are now cleared on
  every contradicting-verb emission and set on every refusal emission
  (including the `WantYesOpposite → WantNo` transitions). Prevents
  duplicate refusal replies to a misbehaving peer. Caught by the
  proptest fuzzer.
- `gateway_telnet` local → remote direction now IAC-escapes outbound 0xFF
  data bytes correctly.
- `gateway_telnet` remote → local direction now parses inbound IAC rather
  than leaking protocol bytes to the user's terminal.

### Changed

- `gateway_ssh` prompt order: host/port/username first, then try pubkey
  auth, prompt for password only if pubkey is rejected. Matches how
  OpenSSH from the command line behaves.
- Hayes S7 default is now `15` seconds (capped internally at 60); the
  Hayes `50` second default was too slow for gateway users.

## [0.3.2] - earlier

- RFC compliance features for Telnet (RFC 854 / 855 / 857 / 858 /
  1073 / 1091 / 1143).
- Drain before "Press any key" to avoid CRLF stickiness.
- Security fixes and minor bug fixes.

## [0.3.1] - earlier

- Added web browser for user manual.
- Minor UI polish.

## [0.3.0] - earlier

- Added configuration options for telnet/SSH/serial servers.
- GUI for configuration editing (eframe/egui).
- Ring emulator and dialup directory.
- Windows build fix for `GetDiskFreeSpaceExW`.
- S-register persistence via `AT&W`.

[Unreleased]: https://github.com/rbryce/xmodem-gateway/compare/v0.3.3...HEAD
[0.3.3]: https://github.com/rbryce/xmodem-gateway/releases/tag/v0.3.3
[0.3.2]: https://github.com/rbryce/xmodem-gateway/releases/tag/v0.3.2
[0.3.1]: https://github.com/rbryce/xmodem-gateway/releases/tag/v0.3.1
[0.3.0]: https://github.com/rbryce/xmodem-gateway/releases/tag/v0.3.0
