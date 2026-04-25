# Vintage Gateway

A telnet-based XMODEM file transfer server, SSH gateway, Hayes-compatible
modem emulator for serial-attached retro hardware, text-mode web browser,
and AI chat client written in Rust. Supports PETSCII (Commodore 64), ANSI,
and ASCII terminals. Designed for local network use with retro and modern
terminal clients.

**[User Manual](http://telnetbible.com/vintage-gateway/index.html)**

Once you run the server on your PC, you can telnet to that server from
anywhere on your network (allow firewall port 2323).

Example: `telnet 192.168.1.160:2323`

This program also serves as a modem emulator. For an Altairduino PRO,
connect directly to the altairduino, and set your modem port to be 2SIO2.
(A6/A7 on mine). Remember, you can configure the serial ports by pressing
stop and aux1 up.

Run IMP8, then hit T for terminal mode on the Altairduino.

Example: `ATDT :2323` — for gateway options: `ATDT vintage-gateway`

Note: For the Altairduino, I simply connected my USB to RS232 adapter to
the 9 pin RS232 connector.

For other machines, you may need to use a NULL modem adapter (Cross RX
and TX).

This should also work with the RC2014 / SC126, etc as well.

Author: Ricky Bryce

## Warning

**The telnet interface is intended for local/private network use only.** Telnet
transmits all data (including credentials) in cleartext. Do not expose the
telnet port to the public internet. The SSH interface provides encrypted access
but is still intended for trusted environments.

### Network Security Behavior

When **security is disabled** (the default), the server only accepts telnet
connections from private IP addresses:

- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 private ranges)
- `127.0.0.0/8` (loopback)
- `169.254.0.0/16` (link-local)
- IPv6 loopback (`::1`), link-local (`fe80::/10`), and unique local (`fd00::/8`)

Connections from public IP addresses are refused with an error message.
Additionally, gateway addresses (those ending in `.1`, such as `192.168.1.1`)
are rejected to prevent accidental exposure through router interfaces.

To accept connections from **any IP address**, you must enable security
(`security_enabled = true` in `vgateway.conf`) and set a strong username and
password. Even with security enabled, running this software on a public network
is **not recommended** — telnet credentials are transmitted in cleartext and can
be intercepted. Use the SSH interface for any non-local access.

## Standards Compliance

### Telnet RFCs

The embedded telnet server and the client half of the Telnet Gateway implement
the core parts of the telnet protocol suite that matter for interactive
terminal and BBS use:

| RFC | Title | Implementation notes |
|-----|-------|----------------------|
| **RFC 854** | Telnet Protocol Specification | IAC framing, IAC IAC data escaping, two-byte command handling. AYT replies with `[Yes]`; IP / BRK surface as ESC to the line-editor; EC translates to DEL (backspace) and EL to NAK (erase-line) so line-input honors them; NOP / DM / AO / GA are consumed. Full TCP urgent-mode SYNCH is not implemented (DM is informational) — per RFC 6093 the urgent mechanism is deprecated because middleboxes routinely strip or mangle the urgent pointer. Outbound 0xFF bytes are escaped as IAC IAC; inbound IAC sequences are consumed transparently. |
| **RFC 855** | Telnet Option Specifications | DO / DONT / WILL / WONT negotiation with per-option state. Options we don't support receive WONT / DONT so the peer doesn't wait. |
| **RFC 857** | Telnet Echo Option | The server advertises WILL ECHO to become the echoing side and honors peer requests for ECHO. |
| **RFC 858** | Suppress Go Ahead Option | WILL SGA / DO SGA to operate in full-duplex character-at-a-time mode (rather than half-duplex GA mode). |
| **RFC 859** | Status Option | `DO STATUS` → `WILL STATUS`; `IAC SB STATUS SEND IAC SE` returns an `IAC SB STATUS IS <state> IAC SE` dump listing every option the server has advertised and not had denied. Usable via the Unix `telnet` client's `status` / `send status` subcommands. |
| **RFC 860** | Timing Mark Option | `DO TIMING-MARK` is answered with `WILL TIMING-MARK` after flushing pending output, providing clients a processing-synchronization point. The response is one-shot — no persistent option state. |
| **RFC 1073** | Window Size Option (NAWS) | Client-reported window dimensions are captured via `IAC SB NAWS <w16><h16> IAC SE` and exposed to the session for layout decisions. |
| **RFC 1091** | Terminal-Type Option (TTYPE) | On client WILL TTYPE the server replies DO, then issues `IAC SB TTYPE SEND IAC SE` and records the first `IS` response. Used as a hint for PETSCII / ANSI / ASCII detection. |
| **RFC 1143** | Q-Method of Option Negotiation | Per-option tracking of advertised DO / WILL / DONT prevents the classic negotiation loop. |

Options not negotiated (BINARY, LINEMODE, ENVIRON, NEW-ENVIRON, TSPEED,
COM-PORT, CHARSET) are explicitly refused with WONT / DONT so the peer
doesn't stall waiting for an answer.

#### Outgoing Telnet Gateway

The Telnet Gateway menu (and internally the RFC 854/855 side of `ATDT
host:port` when used for file transfer) dials out to remote telnet servers.
Compliance operates in two modes controlled by the `telnet_gateway_negotiate`
config flag:

**Reactive mode (default, `telnet_gateway_negotiate = false`)**

The gateway does not send any proactive negotiation offers, so raw-TCP
services on port 23 (legacy MUDs, hand-rolled BBS software, etc.) are not
poked with IAC bytes they don't understand.  It still does:

- Escape outbound 0xFF data bytes as `IAC IAC` so literal 0xFF survives
  the wire without being mistaken for the start of an IAC sequence.
- Parse inbound IAC from the remote and silently consume 2-byte commands
  (NOP, DM, BRK, IP, AO, AYT, EC, EL, GA) and subnegotiation bodies
  instead of leaking them into the user's terminal.
- Accept peer's `WILL ECHO` with `DO ECHO` (always on — raw-TCP services
  never send `WILL ECHO`, so this is safe in both modes).  This fixes the
  silent-typing failure on BBSes that expect the server to echo.
- Refuse every other peer-initiated option: `WILL <opt>` → `DONT <opt>`,
  `DO <opt>` → `WONT <opt>`.  Refusals are one-shot per cycle (RFC 1143
  spirit) so a persistent remote can't drive us into a loop.

**Raw-TCP escape hatch (`telnet_gateway_raw = true`)**

When set, the gateway bypasses its entire telnet-IAC layer: no IAC
escaping on outbound, no IAC parsing on inbound, no negotiation.
Intended for destinations that clearly aren't telnet at all (legacy
MUDs, hand-rolled BBS software).  Supersedes `telnet_gateway_negotiate`.
The Telnet Gateway menu shows the current mode and lets you toggle it
with a single keystroke; the change is saved to `vgateway.conf` so future
sessions start in the selected mode.  Bytes written to the local user
are still IAC-escaped so their telnet client doesn't misinterpret a
stray 0xFF as a protocol byte.

**Cooperative mode (`telnet_gateway_negotiate = true`)**

In addition to everything reactive mode does, the gateway:

- Sends `IAC WILL TTYPE`, `IAC WILL NAWS`, and `IAC DO ECHO` as proactive
  offers at connect time, so BBSes that wait for the client to ask first
  still get echo, terminal-type adaptation, and window-size awareness.
- Responds to `SB TTYPE SEND` with `SB TTYPE IS PETSCII` / `ANSI` / `DUMB`
  depending on the local user's terminal type, so remotes can serve
  appropriate content.
- Responds to `DO NAWS` with `WILL NAWS` plus an immediate `SB NAWS`
  carrying the local user's actual window dimensions (from their own
  NAWS, or terminal-type defaults: 40×25 for PETSCII, 80×24 for ANSI /
  ASCII).  Any 0xFF byte in the width/height is properly IAC-doubled.
- **Forwards NAWS updates mid-session**: if the local user resizes their
  terminal during a gateway session, the new dimensions are captured
  from their `IAC SB NAWS` subnegotiation and relayed to the remote
  server as an updated `SB NAWS`.
- Tracks each option through a **full RFC 1143 six-state Q-method**
  (`No` / `Yes` / `WantYes` / `WantYesOpposite` / `WantNo` /
  `WantNoOpposite`), so mind-changes while a prior WILL or DO is in
  flight resolve cleanly instead of racing into inconsistent state.

The gateway never waits for a reply to any message it sends, so silent
or partially-compliant remote servers do not cause it to stall.  Enable
cooperative mode when dialing real telnet servers; leave it off for
compatibility with raw-TCP destinations.

### Hayes AT Command Set

See [Hayes Compliance Summary](#hayes-compliance-summary) in the Modem
Emulator section for a full command inventory and the three gateway-friendly
default deviations (`AT&D0`, `AT&K0`, `S7=15`).

## Prerequisites

### Debian 13 / Ubuntu

Install build dependencies and the Rust toolchain:

```sh
sudo apt update
sudo apt install -y build-essential pkg-config cmake curl libudev-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the prompts (press 1 for the default installation). Then load the
environment into your current shell:

```sh
source "$HOME/.cargo/env"
```

### Fedora / RHEL / AlmaLinux

```sh
sudo dnf install -y gcc gcc-c++ make cmake pkg-config curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Arch Linux

```sh
sudo pacman -S --needed base-devel cmake curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Windows

1. Download and run the rustup installer from https://rustup.rs
2. When prompted, install the Visual Studio C++ Build Tools (required)
3. Open a new terminal after installation completes

`cmake` is also required. Install it from https://cmake.org/download/ or via
winget:

```
winget install Kitware.CMake
```

### macOS

```sh
xcode-select --install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
brew install cmake
```

### Verify Installation

```sh
rustc --version    # should show 1.85.0 or later
cargo --version
cmake --version
```

## Building

```sh
cargo build --release
```

The binary will be at `target/release/vintage-gateway`.

## Verifying Releases

Pre-built binaries are published to the [GitHub Releases][releases] page
for Linux (x86_64), macOS (aarch64), and Windows (x86_64). Every release
ships with:

- The binary archive (`vintage-gateway-vX.Y.Z-<target>.tar.gz` or `.zip`).
- A SHA-256 checksum (`<archive>.sha256`).
- Optionally a detached GPG signature (`<archive>.asc`) — produced if the
  release signer has a GPG key configured.
- A [Sigstore][sigstore] keyless signature (`<archive>.sig` +
  `<archive>.pem`) bound to the publisher's GitHub identity. Produced on
  every release automatically; no key management required.

[releases]: https://github.com/rickybryce/vintage-gateway/releases
[sigstore]: https://www.sigstore.dev/

### Verifying the checksum

```sh
sha256sum -c vintage-gateway-v0.4.0-x86_64-unknown-linux-gnu.tar.gz.sha256
```

### Verifying the GPG signature (if present)

```sh
gpg --keyserver keys.openpgp.org --recv-keys <KEY_FINGERPRINT>
gpg --verify \
    vintage-gateway-v0.4.0-x86_64-unknown-linux-gnu.tar.gz.asc \
    vintage-gateway-v0.4.0-x86_64-unknown-linux-gnu.tar.gz
```

### Verifying the Sigstore signature

[`cosign`](https://github.com/sigstore/cosign) is required (one-time install,
free):

```sh
cosign verify-blob \
    --certificate vintage-gateway-v0.4.0-x86_64-unknown-linux-gnu.tar.gz.pem \
    --signature   vintage-gateway-v0.4.0-x86_64-unknown-linux-gnu.tar.gz.sig \
    --certificate-identity-regexp "https://github.com/rickybryce/vintage-gateway/.*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    vintage-gateway-v0.4.0-x86_64-unknown-linux-gnu.tar.gz
```

This ties the binary to a specific GitHub Actions workflow run on
this repository.

### OS-level trust prompts

Neither Windows `.exe` nor macOS `.app` bundles ship with commercial
code-signing certificates (those cost $100–400/year and aren't in scope
for a hobby project). As a result:

- **Windows**: SmartScreen shows "Windows protected your PC"; click
  *More info* → *Run anyway*. Verify the SHA-256 and GPG/Sigstore
  signature first.
- **macOS**: Gatekeeper shows "cannot be opened because the developer
  cannot be verified"; right-click → *Open* → *Open*, or remove the
  quarantine attribute with `xattr -d com.apple.quarantine <path>`.
- **Linux**: no equivalent prompt; just verify and run.

If this causes friction in your environment, build from source
(`cargo build --release`) — the result is identical modulo build
reproducibility.

## Running

```sh
./vintage-gateway
```

On first run, a default configuration file `vgateway.conf` is created in the
working directory. The telnet server listens on port 2323 by default.

Connect with any telnet client:

```sh
telnet <server-ip> 2323
```

Or, if the SSH interface is enabled, connect with any SSH client:

```sh
ssh <ssh-user>@<server-ip> -p 2222
```

### Running as a systemd Service (Linux)

A hardened systemd unit file is provided at
[`contrib/systemd/vintage-gateway.service`](contrib/systemd/vintage-gateway.service).
To install:

```sh
# Create a dedicated unprivileged user
sudo useradd --system --home-dir /var/lib/vintage-gateway \
             --shell /usr/sbin/nologin vintage-gateway
sudo install -d -m 0750 -o vintage-gateway -g vintage-gateway \
             /var/lib/vintage-gateway

# Install the binary
sudo install -m 0755 target/release/vintage-gateway /usr/local/bin/

# Install and start the service
sudo install -m 0644 contrib/systemd/vintage-gateway.service \
             /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vintage-gateway.service

# Watch the log
journalctl -u vintage-gateway -f
```

The unit ships with defensive hardening enabled by default:
`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
`ProtectHome`, namespace restrictions, `SystemCallFilter=@system-service`,
capability bounding, and a 512 MiB memory cap.  Edit the file to
loosen anything that breaks your deployment.

Set the telnet server port below 1024 (e.g. 23) by uncommenting the
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE` line and matching
`AmbientCapabilities`.

## GUI Configuration Editor

When `enable_console = true` (the default), a graphical configuration window
opens on startup. The GUI provides:

- **Live console output** -- server log messages stream in the bottom panel
- **Configuration editing** -- all `vgateway.conf` settings can be changed and
  saved without editing the file by hand
- **Serial port auto-detection** -- the Serial Modem section lists detected
  serial ports in a dropdown; click the refresh button to re-scan
- **"More..." popups** -- the Server, File Transfer, and Serial Modem frames
  each have a **More...** button that opens an advanced-options window. The
  File Transfer popup exposes the XMODEM-family timeouts plus the independent
  ZMODEM tunables (handshake, frame timeout, retry cap) side by side.
- **User Manual button** -- opens the PDF user manual on GitHub in your browser
- **Save and Restart Server** -- writes changes to `vgateway.conf` and restarts
  the server so all changes (including security, ports, and credentials) take
  effect immediately

The GUI window closes automatically when the server receives a shutdown signal
(Ctrl+C, SIGTERM, SIGHUP) or when the Save and Restart Server button is
clicked (the GUI reopens after the restart completes). Closing the GUI window
does **not** stop the server -- it continues running headless until a shutdown
signal is received.

To disable the GUI, set `enable_console = false` in `vgateway.conf` or uncheck
"Show GUI on Startup" in the Other Settings section and save.

## Main Menu

After connecting and completing terminal detection (and login, if security is
enabled), the main menu offers:

```
  A  AI Chat
  B  Simple Browser
  C  Configuration
  F  File Transfer
  R  Troubleshooting
  S  SSH Gateway
  T  Telnet Gateway
  W  Weather
  X  Exit
```

## Configuration

Most settings can be changed from within a telnet or SSH session using the
**C** (Configuration) menu, which provides submenus for:

- **E** Security -- toggle login requirement, set telnet/SSH credentials
- **G** Gateway Configuration -- outbound Telnet and SSH Gateway options
- **M** Modem Emulator -- serial port selection and parameters
- **S** Server Configuration -- enable/disable telnet and SSH, set ports
- **F** File Transfer -- submenu with shared transfer directory and
  per-protocol settings pages:
  - **X** XMODEM settings -- negotiation timeout, retry interval
    (C/NAK poke cadence), block timeout, and retry limit (shared with
    XMODEM-1K and YMODEM, which use the same protocol code)
  - **Y** YMODEM settings -- same keys as XMODEM; page calls out the
    shared-family behavior
  - **Z** ZMODEM settings -- independent handshake timeout, retry
    interval (ZRINIT/ZRQINIT re-send cadence), per-frame read timeout,
    and ZRQINIT/ZRPOS/ZDATA retry cap
- **O** Other Settings -- AI API key, browser homepage, weather zip, verbose
  logging, GUI on startup
- **R** Reset Defaults -- restore all settings to factory defaults

All settings are persisted to `vgateway.conf` automatically. You can also edit
`vgateway.conf` by hand. All options:

```ini
# Telnet server: set to false to disable (SSH-only mode)
telnet_enabled = true

# Telnet server port
telnet_port = 2323

# Outgoing Telnet Gateway cooperative negotiation (see Telnet RFCs section).
# Off by default so raw-TCP services on port 23 keep working.
telnet_gateway_negotiate = false

# Outgoing Telnet Gateway raw-TCP escape hatch.
# When true, the gateway disables its telnet-IAC layer entirely and
# treats the remote as raw TCP.  Toggleable live from the Telnet Gateway
# menu (press 'T' at the mode prompt) — changes are persisted here.
telnet_gateway_raw = false

# Show the GUI configuration/console window on startup.
# Set to false when running as a headless service.
enable_console = true

# Security: set to true to require username/password login
security_enabled = false

# Credentials (only used when security_enabled = true)
username = admin
password = changeme

# Directory for file transfers (relative to working directory)
transfer_dir = transfer

# Maximum concurrent telnet sessions
max_sessions = 50

# Idle session timeout in seconds (0 = no timeout)
idle_timeout_secs = 900

# Groq API key for AI Chat (get one at https://console.groq.com/keys)
# Leave empty to disable AI Chat.
groq_api_key =

# Browser homepage URL (loaded automatically when entering the browser)
# Leave empty to start with a blank prompt.
browser_homepage = http://telnetbible.com

# Last-used weather zip code (updated automatically when you check weather)
weather_zip =

# Verbose logging: set to true for detailed XMODEM/YMODEM/ZMODEM protocol diagnostics
verbose = false

# XMODEM-family protocol timeouts (apply to XMODEM, XMODEM-1K, and YMODEM —
# they share the same protocol code path).
# xmodem_negotiation_timeout:        seconds to wait for the peer to start sending.
# xmodem_block_timeout:              seconds to wait for each data block.
# xmodem_max_retries:                retry limit per block.
# xmodem_negotiation_retry_interval: seconds between C/NAK pokes during the
#                                    initial handshake (spec ~10 s, default 7).
xmodem_negotiation_timeout = 45
xmodem_block_timeout = 20
xmodem_max_retries = 10
xmodem_negotiation_retry_interval = 7

# ZMODEM protocol tunables (independent of the XMODEM family).
# zmodem_negotiation_timeout:        seconds to wait for ZRQINIT / ZRINIT handshake.
# zmodem_frame_timeout:              seconds to wait for each header / subpacket.
# zmodem_max_retries:                retry limit for ZRQINIT / ZRPOS / ZDATA frames.
# zmodem_negotiation_retry_interval: seconds between ZRINIT / ZRQINIT re-sends
#                                    during the handshake (default 5).
zmodem_negotiation_timeout = 45
zmodem_frame_timeout = 30
zmodem_max_retries = 10
zmodem_negotiation_retry_interval = 5

# Serial modem emulation (Hayes AT commands)
# Set serial_enabled = true and configure the port to activate.
serial_enabled = false

# Serial port device (e.g. /dev/ttyUSB0 on Linux, COM3 on Windows)
# Leave empty if not configured. Use the Modem Emulator menu to detect ports.
serial_port =

# Serial port parameters
serial_baud = 9600
serial_databits = 8
serial_parity = none
serial_stopbits = 1
serial_flowcontrol = none

# Saved modem settings (written by AT&W, restored by ATZ)
serial_echo = true
serial_verbose = true
serial_quiet = false
serial_s_regs = 5,0,43,13,10,8,2,15,2,6,14,95,50,0,0,0,0,0,0,0,0,0,0,0,0,5,1

# Hayes extended command state (written by AT&W, restored by ATZ)
# serial_x_code:    ATX level 0-4 (4 = all extended result codes, Hayes default)
# serial_dtr_mode:  AT&D 0-3 (0 = ignore DTR, gateway-friendly default)
# serial_flow_mode: AT&K 0-4 (0 = no flow control at modem layer,
#                   gateway-friendly default; physical port flow control
#                   is still controlled by serial_flowcontrol above)
# serial_dcd_mode:  AT&C 0-1 (1 = DCD reflects carrier, Hayes default)
serial_x_code = 4
serial_dtr_mode = 0
serial_flow_mode = 0
serial_dcd_mode = 1

# Hayes stored phone-number slots (AT&Zn=s sets, ATDSn dials).  Empty = unset.
serial_stored_0 =
serial_stored_1 =
serial_stored_2 =
serial_stored_3 =

# SSH server interface (encrypted access to the gateway)
# Set ssh_enabled = true to activate. Uses its own credentials.
ssh_enabled = false

# SSH server port
ssh_port = 2222

# SSH credentials (independent of telnet credentials)
ssh_username = admin
ssh_password = changeme
```

### Setting Up Authentication

To require a username and password, either use the in-app Configuration menu
(**C** > **E** Security) or edit `vgateway.conf` by hand:

1. Open `vgateway.conf` in a text editor
2. Set `security_enabled = true`
3. Change `username` and `password` to your desired credentials
4. Restart the server

When enabled, users must authenticate after terminal detection. Failed login
attempts are tracked per IP address -- after 3 failures, the IP is locked out
for 5 minutes.

**Note:** Credentials are stored in plaintext in `vgateway.conf`. This is
consistent with the telnet protocol itself, which transmits all data
(including passwords) in cleartext. Do not reuse sensitive passwords here.
This authentication is intended as a lightweight access control for private
networks, not as a security boundary.

### Setting Up AI Chat

The AI Chat feature uses the [Groq API](https://groq.com), which provides free
access to fast LLM inference. To enable it:

1. Go to https://console.groq.com and create a free account
2. Navigate to **API Keys** and generate a new key (starts with `gsk_`)
3. Set the key via Configuration > Other Settings > **A** (Set AI API key), or
   open `vgateway.conf` and set: `groq_api_key = gsk_your_key_here`
4. Restart the server

If no API key is configured, selecting AI Chat from the menu will display
instructions on how to obtain one.

### Setting Up the Browser Homepage

The browser loads `http://telnetbible.com` by default. To change it, use
Configuration > Other Settings > **B** (Set browser homepage), or edit
`vgateway.conf`:

1. Open `vgateway.conf`
2. Set `browser_homepage` to a URL, e.g.: `browser_homepage = example.com`
3. Restart the server

## Terminal Support

On connect, the server asks the user to press **Backspace** to detect the
terminal type:

| Byte received | Terminal type | Description |
|---------------|---------------|-------------|
| 0x14          | PETSCII       | Commodore 64 (40-column, single-byte color codes) |
| 0x08 or 0x7F  | ANSI          | Modern terminal with escape sequence color |
| Other         | ASCII         | Plain text, no color |

After detection, the server asks whether to enable color. The user must press
Y or N to continue; no default is applied.

## Transferring Files

### Supported Protocols

The gateway implements four members of the XMODEM family, selectable
per-transfer from menus on the gateway side:

| Protocol | Block size | CRC | Direction | Notes |
|----------|------------|-----|-----------|-------|
| **XMODEM** | 128 B (SOH) | CRC-16 or checksum | up/down | Auto-detects CRC vs. checksum on receive; classic single-file. |
| **XMODEM-1K** | 1024 B (STX) | CRC-16 | up/down | Download option; on upload the XMODEM/YMODEM branch accepts STX blocks transparently. Opportunistically falls back to SOH if the peer NAKs the first STX. |
| **YMODEM** | 1024 B + block-0 header | CRC-16 | up/down | Block 0 carries filename + size; the receive path auto-detects it. |
| **ZMODEM** | variable subpackets (1 K default) | CRC-16 out, CRC-16 or CRC-32 in | up/down | Full Forsberg spec: ZRQINIT handshake, ZDLE escaping, ZSKIP, batch sends and receives. On upload the first file is saved under the name you entered; subsequent files in a batch use the sender's filename (validated, collisions skipped via ZSKIP). |

On upload, the gateway offers **XMODEM / YMODEM** (variant auto-detected) or
**ZMODEM**. On download, you pick the specific variant you want.

### Uploading a File to the Server

1. Connect via telnet and navigate to **F** (File Transfer)
2. Press **U** (Upload)
3. Enter a filename (letters, numbers, dots, hyphens, underscores only; max 64
   characters; cannot start with a dot, cannot contain `..`, must include at
   least one letter or digit)
4. On the **SELECT UPLOAD PROTOCOL** screen, press **X** (XMODEM / YMODEM —
   block size, CRC mode, and batch header are auto-detected) or **Z** (ZMODEM)
5. The server displays "Start XMODEM/YMODEM send now" or "Start ZMODEM send
   now" and waits up to 45 seconds
6. In your terminal client, start the matching upload
   - Most terminal programs have a "Send File" or "Upload" option under a
     Transfer or File menu
   - ExtraPutty: **File Transfer → Zmodem → Send**; SyncTerm: **Ctrl-PgUp**
7. On completion, the server reports bytes, blocks, and elapsed time. For
   ZMODEM batches, every file the sender transmits is listed (saved or
   skipped)

### Downloading a File from the Server

1. Navigate to **F** (File Transfer), then press **D** (Download)
2. The server lists files in the current transfer directory (paginated, 10 per
   page)
3. Enter the number of the file to download
4. On the **SELECT PROTOCOL** screen, choose **X** (XMODEM), **1** (XMODEM-1K),
   **Y** (YMODEM), or **Z** (ZMODEM)
5. The server prompts "Start XMODEM/YMODEM/ZMODEM receive now" and waits up
   to 45 seconds
6. In your terminal client, start the matching receive and choose where to
   save the file locally (ZMODEM auto-starts in most modern terminals)
7. On completion, the server reports the transfer result

### Other File Operations

- **X** -- Delete a file (with confirmation)
- **C** -- Change to a subdirectory within the transfer directory
- **I** -- Toggle IAC escaping on/off (needed when transferring binary files
  over telnet that contain 0xFF bytes)

### IAC Escaping

Telnet reserves byte 0xFF as the IAC (Interpret As Command) marker. When
transferring binary files that may contain 0xFF, enable IAC escaping with the
**I** toggle in the File Transfer menu. Both the server and your terminal client
must agree on whether IAC escaping is active. For text files or when your client
handles this automatically, leave it off (the default).

## SSH Server

The SSH server provides encrypted access to the same gateway menus and features
available over telnet. This is useful when connecting from modern clients where
encryption is preferred over plaintext telnet.

### Enabling the SSH Server

Use Configuration > Server Configuration to toggle SSH and set the port, and
Configuration > Security to set SSH credentials. Or edit `vgateway.conf` by hand:

1. Set `ssh_enabled = true`
2. Change `ssh_username` and `ssh_password` to your desired credentials
3. Optionally change `ssh_port` (default 2222)
4. Restart the server

On first start with SSH enabled, the server generates an Ed25519 host key and
saves it to `vintage_ssh_host_key` in the working directory. This key is reused
on subsequent starts so that clients can verify the server's identity.

### Connecting

```sh
ssh <username>@<server-ip> -p 2222
```

After authenticating, you are presented with the same Vintage Gateway menu
system as a telnet connection, using ANSI terminal mode. All features (file
transfer, SSH/telnet gateway, browser, AI chat, modem emulator, weather) are
available.

### SSH vs Telnet Credentials

The SSH server has its own username and password (`ssh_username` /
`ssh_password`), independent of the telnet credentials (`username` /
`password`). When `vgateway.conf` is first created, both sets default to the same
values (`admin` / `changeme`). After that, each set can be changed
independently.

**Note:** SSH credentials in `vgateway.conf` are stored in plaintext. While the
SSH connection itself is encrypted, the config file is not. Protect it with
appropriate file permissions.

## SSH Gateway

The SSH Gateway allows you to connect through the server to a remote SSH host.
This is useful for accessing SSH servers from terminals that only support telnet
(such as a Commodore 64).

1. From the main menu, press **S** (SSH Gateway)
2. Optionally press **K** at the first prompt to display the gateway's public
   key (see *Public-Key Authentication* below)
3. Enter the remote host, port (default 22), and username
4. The gateway attempts public-key authentication using its own keypair first
5. If the remote doesn't trust the gateway key, you are prompted for a password
6. Once connected, you have a full interactive shell on the remote server
7. Press **ESC** twice to disconnect from the SSH session

The server acts as a proxy between your telnet client and the remote SSH server.
All input is forwarded to the SSH session, and all output is sent back to your
terminal. Telnet line-ending conventions (CR+LF, CR+NUL) are automatically
normalized to bare CR for SSH compatibility.

For PETSCII and ASCII terminals, ANSI escape sequences from the remote host are
automatically stripped, and text is converted to the appropriate encoding. ANSI
terminals receive the raw output unmodified. The PTY size is set to 40x25 for
PETSCII and 80x24 for ANSI/ASCII terminals.

### Public-Key Authentication

On the first outbound SSH dial, the gateway generates an Ed25519 client keypair
and stores it as `vintage_gateway_ssh_key` (0o600 on Unix). Every subsequent
dial tries public-key authentication with this key *before* falling back to a
password prompt. If the remote accepts the key, you skip the password prompt
entirely — identical to how OpenSSH from the command line behaves.

To set up passwordless login to a particular remote:

1. Open the SSH Gateway menu and press **K** — the gateway's public key is
   displayed in the standard `ssh-ed25519 AAAA…` OpenSSH format.
2. Copy that line into the remote server's `~/.ssh/authorized_keys` file.
3. Future dials to that host skip the password prompt.

If the remote doesn't have the gateway's key in its `authorized_keys`, you see
a one-line notice (`Pubkey not accepted — password required.`) and the
password prompt appears as before.

### Host-Key Verification

The first time you dial a new SSH server, the gateway shows the server's
SHA-256 fingerprint and asks whether to trust it (TOFU — trust-on-first-use).
If accepted, the fingerprint is saved to `gateway_hosts` (0o600 on Unix) and
checked on every subsequent dial. A changed key produces a prominent
`WARNING: HOST KEY HAS CHANGED!` with the option to update or abort.

All host-key trust decisions (first-time accept, update, and reject) are
written to the server log so there is a forensic trail if a key change turns
out to be a man-in-the-middle attempt.

### SSH Gateway vs SSH Server

`gateway_hosts` holds the *remote* servers' public keys (similar to an OpenSSH
client's `~/.ssh/known_hosts`). `vintage_ssh_host_key` is the Vintage Gateway's
*own* SSH server host key. `vintage_gateway_ssh_key` is the gateway's outgoing-
client keypair used for public-key authentication to remote servers. All three
are independent.

## Telnet Gateway

The Telnet Gateway connects through the server to a remote telnet host. This is
useful for accessing BBS systems or other telnet services from retro terminals.

1. From the main menu, press **T** (Telnet Gateway)
2. At the mode prompt, press **T** to toggle between `Telnet protocol` and
   `Raw TCP` mode if needed (see below), or any other key to continue
3. Enter the remote host and port (default 23)
4. Once connected, all input and output is proxied between your terminal and the
   remote server
5. Press **ESC** twice to disconnect

For PETSCII and ASCII terminals, ANSI escape sequences from the remote host are
automatically filtered.

### Protocol Modes

The gateway has three modes of operation, all documented in the [Telnet RFCs](#telnet-rfcs)
section above. In short:

- **Telnet protocol (default)** — the gateway parses IAC framing in both
  directions, accepts cooperative ECHO from the remote, refuses other options.
  Works with any real telnet server.
- **Cooperative mode** (`telnet_gateway_negotiate = true` in `vgateway.conf`) —
  adds proactive TTYPE, NAWS, and DO ECHO offers so modern BBSes can adapt
  content and render full-screen layouts at your actual window size.
- **Raw TCP** (toggled with **T** at the gateway menu, saved persistently) —
  the IAC layer is disabled entirely. Use this when dialing destinations that
  don't speak telnet at all (legacy MUDs, hand-rolled BBS software, some
  services on port 23). The toggle persists to `vgateway.conf` so you only need
  to set it once per destination type.

## Modem Emulator

The modem emulator provides Hayes AT command emulation on a physical serial
port. This allows retro hardware (Commodore 64, CP/M machines, etc.) to connect
to the gateway and to remote telnet hosts using a serial connection and standard
modem commands.

### Setting Up

1. From the main menu, press **C** (Configuration)
2. Press **M** (Modem Emulator)
3. Press **E** to enable the emulator
4. Press **S** to select a serial port (auto-detected)
5. Configure baud rate, data bits, parity, stop bits, and flow control as needed
6. Press **Q** to apply -- settings take effect immediately (no restart needed)

Or edit `vgateway.conf` directly and restart the server.

### Supported AT Commands

| Command | Action |
|---------|--------|
| `AT`    | OK (attention) |
| `AT?`   | Show AT command help |
| `ATZ`   | Reset modem to stored settings (saved by AT&W) |
| `AT&F`  | Reset modem to factory defaults (gateway-friendly, see below) |
| `AT&W`  | Save current modem settings to `vgateway.conf` |
| `AT&V`  | Display current modem configuration |
| `ATE0` / `ATE1` | Echo off / on |
| `ATV0` / `ATV1` | Numeric / verbose result codes |
| `ATQ0` / `ATQ1` | Result codes on / quiet mode (suppress results) |
| `ATI` / `ATI0`–`ATI7` | Identification variants (product ID, ROM checksum, ROM test, firmware, OEM, country, diag, product info) |
| `ATH`   | Hang up (close any active connection) |
| `ATA`   | Answer incoming ring |
| `ATO`   | Return to online mode (resume after `+++` escape) |
| `ATX0`–`ATX4` | Result code verbosity (see table below) |
| `AT&C0` / `AT&C1` | DCD always on / DCD reflects carrier (default) |
| `AT&D0`–`AT&D3` | DTR handling (0 = ignore, default; 1 = cmd mode on drop; 2 = hang up; 3 = hang up + reset) |
| `AT&K0`–`AT&K4` | Modem-layer flow control (0 = none, default; 1 = reserved; 3 = RTS/CTS; 4 = XON/XOFF) |
| `ATS?`  | Show S-register help |
| `ATS`*n*`?` | Query S-register *n* (returns 3-digit value) |
| `ATS`*n*`=`*v* | Set S-register *n* to value *v* (0–255). Range S0–S26 |
| `ATDL`  | Redial last number |
| `ATDS` / `ATDS`*n* | Dial stored number from slot *n* (0–3; default 0) |
| `AT&Z`*n*`=`*s* | Store phone number or host *s* in slot *n* (0–3) |
| `ATDT vintage-gateway` | Connect to this gateway's menus |
| `ATDT host:port` | Dial a remote telnet host |
| `ATDP host:port` | Pulse dial (same as ATDT — no distinction for TCP) |
| `A/`    | Repeat the last command (no `AT` prefix, no CR required) |
| `+++`   | Return to command mode (with guard time from S12) |

Unrecognized commands (`ATB`, `ATC`, `ATL`, `ATM`, `AT&B`, `AT&G`, `AT&J`,
`AT&S`, `AT&T`, `AT&Y`, etc.) are accepted and return `OK` so that legacy
init strings don't halt with `ERROR` on commands the emulator has no
hardware to implement.

**Dial modifiers** inside phone-number dial strings:

| Modifier | Action |
|----------|--------|
| `,` | Pause for S8 seconds (default 2s) before continuing |
| `W` | Wait for dial tone (adds S6 seconds, virtual) |
| `;` | After dial, return to command mode instead of going online |
| `*`, `#` | DTMF digits, preserved for phone-number lookup |
| `P`, `T`, `@`, `!` | Pulse/tone/quiet/hookflash selectors, ignored |

Modifiers are only honored when the dial string looks like a phone number.
Hostnames like `pine.example.com` or `www.example.com` are not stripped.

**Result codes and ATX levels:** In verbose mode (default) results are text
(`OK`, `CONNECT`, `NO CARRIER`, `ERROR`). In numeric mode (`ATV0`) results are
digits. Quiet mode (`ATQ1`) suppresses all result codes. The ATX level
controls which codes the modem may emit and whether `CONNECT` includes the
line speed:

| Level | Extended codes | CONNECT format |
|-------|----------------|----------------|
| X0 | Basic only; BUSY / NO DIALTONE / NO ANSWER collapse to NO CARRIER | `CONNECT` (code 1) |
| X1 | Basic + baud in CONNECT | `CONNECT <baud>` (code per baud) |
| X2 | Adds NO DIALTONE detection | `CONNECT <baud>` |
| X3 | Adds BUSY detection | `CONNECT <baud>` |
| X4 | Full extended set (gateway default) | `CONNECT <baud>` |

Numeric `CONNECT` codes follow Hayes conventions: 1 = 300, 5 = 1200,
10 = 2400, 12 = 9600, 16 = 19200, 28 = 38400, 87 = 115200. Non-standard
baud rates fall back to code 1.

**S-registers:** Query with `ATSn?`, set with `ATSn=v`, or type `ATS?` for help.
`AT&W` saves all registers to `vgateway.conf`; `ATZ` restores saved values;
`AT&F` resets to gateway-friendly factory defaults.

| Register | Default | Description |
|----------|---------|-------------|
| S0  | 5   | Auto-answer ring count (0 = disabled) |
| S1  | 0   | Ring counter (current) |
| S2  | 43  | Escape character (43 = `+`) |
| S3  | 13  | Carriage return character |
| S4  | 10  | Line feed character |
| S5  | 8   | Backspace character |
| S6  | 2   | Wait for dial tone (seconds) |
| S7  | **15** | Wait for carrier (seconds) — Hayes default is 50; reduced here so failed dials return quickly. Capped internally at 60 s. |
| S8  | 2   | Comma pause time (seconds) |
| S9  | 6   | Carrier detect response time (1/10s) |
| S10 | 14  | Carrier loss disconnect time (1/10s) |
| S11 | 95  | DTMF tone duration (milliseconds) |
| S12 | 50  | Escape guard time (1/50s; 50 = 1 second) |
| S13–S24 | 0 | Reserved. Stored and persisted so legacy init strings that probe these registers don't halt with `ERROR`, but they have no effect on the emulator. |
| S25 | 5   | DTR detect time (1/100s). Reserved — no DTR pin. |
| S26 | 1   | RTS-to-CTS delay (1/100s). Reserved — no RTS/CTS pins. |

Keep `S3`, `S4`, and `S5` at distinct values. Command-mode line editing
dispatches on the raw byte: the CR branch is checked before BS, so setting
`S3 = 8` would cause backspace to terminate the line. Leaving S3/S4/S5 at
their Hayes defaults (13/10/8) avoids this.

### Hayes Compliance Summary

The emulator implements the Hayes Smartmodem AT command set: AT, ATZ, AT&F,
AT&W, AT&V, ATE, ATV, ATQ, ATI (I0–I7), ATH, ATA, ATO, ATX, AT&C, AT&D,
AT&K, AT&Z (stored numbers), ATD (with T/P/L/S variants), ATSn, S-registers
S0–S26, the `A/` repeat-last-command shortcut, and the `+++` escape with
S2/S12 guard-time semantics. `AT&W` persists every Hayes setting — echo,
verbose, quiet, X, &C, &D, &K, all 27 S-registers, and four stored-number
slots — to `vgateway.conf`; `ATZ` restores them. Numeric and verbose result
codes honor the ATX level.

Commands the emulator can't meaningfully implement over TCP (`ATB`, `ATC`,
`ATL`, `ATM`, `AT&B`, `AT&G`, `AT&J`, `AT&S`, `AT&T`, `AT&Y`) are accepted
and return `OK` so that legacy init strings run to completion.

**Gateway-friendly default deviations:**

| Setting | Gateway default | Hayes default | Why we differ |
|---------|-----------------|---------------|---------------|
| `AT&D` | `&D0` (ignore DTR) | `&D2` (hang up on DTR drop) | Many retro clients don't drive DTR correctly. `&D2` would cause spurious disconnects. |
| `AT&K` | `&K0` (no modem-level flow control) | `&K3` (RTS/CTS) | C64, CP/M, and similar clients rarely implement hardware flow control. The physical port flow control is still set by `serial_flowcontrol` in `vgateway.conf`. |
| `S7` | 15 seconds | 50 seconds | Keeps failed TCP dials responsive. Raising S7 is allowed up to an internal cap of 60 s. |

All three deviations can be overridden interactively (e.g. `AT&D2`,
`AT&K3`, `ATS7=50`) and persisted with `AT&W`.

**Implementation notes:**

- `AT&D`, `AT&K`, and `AT&C` are parsed, stored, displayed in `AT&V`, and
  persisted — but their effects on RS-232 hardware signalling (DTR monitoring,
  RTS/CTS handshake, DCD line) are not enforced by the emulator. See the
  **Limitations** section below for why.
- `ATX1`–`ATX4` all affect result codes and `CONNECT` formatting.
- `ATS6` (wait-for-dial-tone) and `ATS8` (comma pause) sleep for the
  configured number of seconds before the TCP connect, summed per modifier
  and capped at 60 seconds total.
- The `+++` escape follows the Hayes timing spec (one guard time of silence
  before the `+` triple, then another guard time after). Setting `ATS12=0`
  or `ATS2>127` disables escape detection.

### Escaping and Resuming

The `+++` escape sequence returns to command mode while keeping the connection
alive. Type `ATO` to resume the connection, or `ATH` to hang up. This follows
standard Hayes modem behavior: one second of silence, then `+++`, then another
second of silence.

### Ring Emulator

Telnet and SSH users can simulate an incoming phone call to the serial device
from the Modem Emulator menu (**I** — Ring emulator). The modem sends `RING`
to the serial port at standard US phone cadence (every 6 seconds). After S0
rings (default 5), the modem auto-answers and the serial device receives the
Vintage Gateway main menu, just as if it had dialed in with
`ATDT vintage-gateway`. The serial device can also answer manually with `ATA`
during ringing.

### Serial Safety

When changing serial port parameters from a serial session, the server asks
for confirmation. If there is no response within 60 seconds (e.g., because the
terminal settings no longer match), the settings are automatically reverted.
This prevents lockout when accidentally misconfiguring the serial port.

### Dialup Mapping

The Dialup Mapping feature (modem menu **D**) lets you map phone numbers to
`host:port` targets. When a number is dialed with `ATDT`, `ATDP`, or `ATD`,
the server looks up the number and connects to the mapped host instead.

A built-in entry maps **1001000** to the local Vintage Gateway menu (equivalent
to `ATDT vintage-gateway`). This entry cannot be deleted.

Mappings are stored in `dialup.conf` (created automatically on first access
with a default starter entry). Phone numbers are matched by digits only --
formatting characters like dashes, spaces, and parentheses are ignored, so
`555-1234` and `5551234` are treated as the same number.

If a dialed number has no mapping, the modem returns `NO CARRIER`. You can
still dial hostnames and `host:port` targets directly -- mappings only apply
when the dial string looks like a phone number (digits and formatting only, no
letters or dots).

### Limitations

This is a software modem emulator, not a real modem. The Hayes command set
(including `AT&C`, `AT&D`, `AT&K`) is fully parsed, stored, persisted via
`AT&W`, and displayed in `AT&V`, but the emulator does not drive the RS-232
hardware signal pins that those commands nominally control:

- **DCD (Data Carrier Detect, pin 1)** -- A real modem asserts DCD when a
  carrier is established with the remote modem. `AT&C1` is accepted and
  persisted, but this emulator does not drive DCD, so the serial device has
  no hardware indication that a connection is active.
- **RI (Ring Indicator, pin 9)** -- A real modem asserts RI when an incoming
  call is ringing. The ring emulator sends `RING` result codes over the
  serial data line, but the RI pin is never driven.
- **DSR (Data Set Ready, pin 6)** -- A real modem asserts DSR when powered
  on and ready. This emulator does not control DSR.
- **DTR (Data Terminal Ready, pin 4)** -- A real modem monitors DTR from the
  terminal to detect hangup requests. `AT&D2`/`AT&D3` is accepted and
  persisted, but the emulator does not read DTR (semantics vary by
  USB-to-serial adapter and platform). Use `ATH` or `+++` to hang up.
- **CTS/RTS (Clear to Send / Request to Send, pins 8/7)** -- `AT&K3`/`AT&K4`
  is accepted and persisted. Actual hardware or software flow control on the
  wire is controlled by the `serial_flowcontrol` setting in `vgateway.conf`
  (not by `AT&K`), so retro clients that can't do RTS/CTS keep working at
  the default `serial_flowcontrol = none`.

Most retro terminal software works fine without these signals, especially
when configured to ignore DCD (sometimes labeled "Force DTR" or "Ignore
Carrier" in the terminal program settings). If your software requires DCD to
be asserted before it will communicate, check its configuration for an
option to disable carrier detection.

## Web Browser

The built-in text-mode web browser renders HTML pages as plain text with
numbered link references. It works on all terminal types, including 40-column
PETSCII screens.

### Browsing a Page

1. From the main menu, press **B** (Simple Browser)
2. Enter a URL (e.g. `example.com`) or a search query (e.g. `rust programming`)
   - URLs without a scheme automatically get `https://` prepended
   - Text without dots is treated as a search query and sent to DuckDuckGo
3. The page is fetched, converted to plain text, and displayed with pagination

### Understanding Links

When a page is displayed, clickable links are marked with numbered tags like
**[1]**, **[2]**, **[3]** next to the linked text. To follow a link, press
**L** and enter the link number.

### Page Navigation Commands

| Key   | Action                              |
|-------|-------------------------------------|
| N / P | Next page / Previous page           |
| T / E | Jump to Top / End of page           |
| L     | Follow a link by number             |
| G     | Go to a new URL or search query     |
| S     | Search for text within the page     |
| F     | Fill out and submit forms           |
| K     | Save current page as a bookmark     |
| B     | Go back to the previous page        |
| R     | Reload the current page             |
| H     | Show help                           |
| Q     | Close page (return to browser home) |
| ESC   | Exit browser to main menu           |

### Bookmarks

- Press **K** while viewing a page to save it as a bookmark
- Press **K** on the browser home screen to open your saved bookmarks
- Select a bookmark by number to navigate to it
- Press **D** in the bookmarks list, then enter a number to delete one
- Up to 100 bookmarks are stored in `bookmarks.txt` next to the binary

### Forms

Many web pages contain forms (search boxes, login fields, etc.). When forms are
detected, the status line shows the form count. Press **F** to interact:

1. If multiple forms exist, select one by number
2. Edit fields by entering the field number
   - Text fields: type a new value
   - Select dropdowns: choose an option by number
   - Checkboxes and radio buttons: toggle or select
3. Press **S** to submit the form, or **Q** to cancel

### Browser Limits

- Maximum page size: 1 MB
- Maximum rendered lines: 5,000
- HTTP request timeout: 15 seconds
- Page history depth: 50 pages
- HTTPS connections that fail due to TLS errors automatically retry over HTTP

### Gopher Protocol

The browser supports the Gopher protocol alongside HTTP/HTTPS. Gopher is a
text-native protocol that predates the web and renders beautifully on retro
terminals, including 40-column PETSCII screens.

To browse a Gopher server, press **G** and enter a `gopher://` URL:

```
gopher://gopher.floodgap.com
gopher://gopher.quux.org
```

Gopher directory listings are displayed with numbered links, just like web
pages. Text files are displayed as plain text. Gopher search items (type 7)
automatically prompt for a search query before fetching results. All browser
features (pagination, history, back, bookmarks) work with Gopher URLs.

## AI Chat

AI Chat provides an interactive question-and-answer interface powered by the
Groq API. Requires a Groq API key (see [Setting Up AI Chat](#setting-up-ai-chat)
above).

1. From the main menu, press **A** (AI Chat)
2. Type a question and press Enter
3. The server shows "Thinking..." while waiting for the response
4. The answer is displayed with pagination (**N** next, **P** previous, **Q** done)
5. From the answer screen, type a new question to continue the conversation,
   or press **Q** to return to the main menu

Responses are word-wrapped to fit the terminal width (38 columns for PETSCII,
78 for ANSI/ASCII).

## Weather

The Weather feature displays current conditions and a 3-day forecast for any
US zip code, powered by [Open-Meteo](https://open-meteo.com) (free, no API
key required).

1. From the main menu, press **W** (Weather)
2. Enter a 5-digit US zip code, or press Enter to use the last one
3. Current temperature, humidity, wind, and a 3-day forecast are displayed

The last-used zip code is saved to `vgateway.conf` so it becomes the default
for all future sessions.

## Signals

The server handles POSIX signals for graceful shutdown:

- **SIGINT** (Ctrl+C) -- Shut down, notify all connected sessions
- **SIGTERM** -- Shut down (e.g., from `kill` or systemd)
- **SIGHUP** -- Shut down

## Disclaimer

This software is provided on an "as is" basis, without warranties of any kind,
express or implied. Use at your own risk. The author is not responsible for any
data loss, security breaches, or damages resulting from the use of this
software. The user is solely responsible for securing their own network,
credentials, and data. Telnet is an inherently insecure protocol -- do not use
this software on untrusted networks.

Portions of this project were developed with the assistance of AI tools 
including Claude Code.

## License

This project is licensed under the [GNU General Public License v3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html) (GPL-3.0-or-later).
