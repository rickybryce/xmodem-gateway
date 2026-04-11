# XMODEM Gateway

A telnet-based XMODEM file transfer server, SSH gateway, text-mode web browser,
and AI chat client written in Rust. Supports PETSCII (Commodore 64), ANSI, and
ASCII terminals. Designed for local network use with retro and modern terminal
clients.

Author: Ricky Bryce
Co-Author: Claude (Anthropic)

## Warning

**The telnet interface is intended for local/private network use only.** Telnet
transmits all data (including credentials) in cleartext. Do not expose the
telnet port to the public internet. The SSH interface provides encrypted access
but is still intended for trusted environments.

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

The binary will be at `target/release/xmodem-gateway`.

## Running

```sh
./xmodem-gateway
```

On first run, a default configuration file `xmodem.conf` is created in the
working directory. The telnet server listens on port 2323 by default.

Connect with any telnet client:

```sh
telnet <server-ip> 2323
```

Or, if the SSH interface is enabled, connect with any SSH client:

```sh
ssh <ssh-user>@<server-ip> -p 2222
```

## Main Menu

After connecting and completing terminal detection (and login, if security is
enabled), the main menu offers:

```
  A  AI Chat
  B  Simple Browser
  E  Serial Gateway  (telnet/SSH only)
  F  File Transfer
  M  Modem Emulator
  R  Troubleshooting
  S  SSH Gateway
  T  Telnet Gateway
  W  Weather
  X  Exit
```

## Configuration

Edit `xmodem.conf` in the same directory as the binary. All options:

```ini
# Telnet server port
telnet_port = 2323

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

# Groq API key for AI Chat (leave empty to disable)
groq_api_key =

# URL to load automatically when entering the browser (leave empty for none)
browser_homepage =

# Enable verbose XMODEM protocol logging to stderr
verbose = false

# Serial modem emulation (Hayes AT commands)
serial_enabled = false
serial_port =
serial_baud = 9600
serial_databits = 8
serial_parity = none
serial_stopbits = 1
serial_flowcontrol = none

# SSH server interface (encrypted access)
ssh_enabled = false
ssh_port = 2222
ssh_username = admin
ssh_password = changeme
```

### Setting Up Authentication

To require a username and password:

1. Open `xmodem.conf` in a text editor
2. Set `security_enabled = true`
3. Change `username` and `password` to your desired credentials
4. Restart the server

When enabled, users must authenticate after terminal detection. Failed login
attempts are tracked per IP address -- after 3 failures, the IP is locked out
for 5 minutes.

**Note:** Credentials are stored in plaintext in `xmodem.conf`. This is
consistent with the telnet protocol itself, which transmits all data
(including passwords) in cleartext. Do not reuse sensitive passwords here.
This authentication is intended as a lightweight access control for private
networks, not as a security boundary.

### Setting Up AI Chat

The AI Chat feature uses the [Groq API](https://groq.com), which provides free
access to fast LLM inference. To enable it:

1. Go to https://console.groq.com and create a free account
2. Navigate to **API Keys** and generate a new key (starts with `gsk_`)
3. Open `xmodem.conf` and set: `groq_api_key = gsk_your_key_here`
4. Restart the server

If no API key is configured, selecting AI Chat from the menu will display
instructions on how to obtain one.

### Setting Up the Browser Homepage

To have the browser automatically load a page when opened:

1. Open `xmodem.conf`
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

After detection, the server asks whether to enable color. PETSCII defaults to
color on; ANSI and ASCII default to color off but can opt in.

## Transferring Files

### Uploading a File to the Server

1. Connect via telnet and navigate to **F** (File Transfer)
2. Press **U** (Upload)
3. Enter a filename (letters, numbers, dots, hyphens, underscores only; max 64
   characters)
4. The server displays "Begin XMODEM send now" and waits up to 90 seconds
5. In your terminal client, start an XMODEM send of the local file
   - Most terminal programs have a "Send File" or "Upload" option under a
     Transfer or File menu
   - Select XMODEM as the protocol
6. The transfer runs at 128-byte blocks with CRC-16 error checking (falls back
   to checksum mode if the client does not support CRC)
7. On completion, the server reports bytes, blocks, and elapsed time

### Downloading a File from the Server

1. Navigate to **F** (File Transfer), then press **D** (Download)
2. The server lists files in the current transfer directory (paginated, 10 per
   page)
3. Enter the number of the file to download
4. The server displays "Start XMODEM receive now" and waits up to 90 seconds
5. In your terminal client, start an XMODEM receive
   - Select XMODEM as the protocol
   - Choose where to save the file locally
6. On completion, the server reports the transfer result

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

## Serial Gateway

The Serial Gateway allows telnet and SSH users to interact directly with a
device connected to the serial port. This is useful for remote access to
equipment that has a serial console (routers, switches, embedded systems, retro
hardware, etc.).

1. From the main menu, press **E** (Serial Gateway)
2. The server connects you to the configured serial port
3. All input and output is proxied between your terminal and the serial device
4. Press **ESC** twice (or **<-** twice on PETSCII) to disconnect

### Requirements

- The serial port must be enabled and configured (via `xmodem.conf` or the
  Modem Emulator menu)
- The modem emulator must not have an active connection (the serial port
  cannot be shared while the modem is in online mode)

### Restrictions

- **Serial users** do not see the Serial Gateway option (prevents feedback
  loops where a serial device would interact with its own port)
- **SSH snooping blocked**: If the device on the serial port is currently
  using the SSH Gateway feature, the Serial Gateway is disabled. This
  prevents telnet/SSH users from observing encrypted SSH sessions in transit.

## SSH Server

The SSH server provides encrypted access to the same gateway menus and features
available over telnet. This is useful when connecting from modern clients where
encryption is preferred over plaintext telnet.

### Enabling the SSH Server

1. Open `xmodem.conf`
2. Set `ssh_enabled = true`
3. Change `ssh_username` and `ssh_password` to your desired credentials
4. Optionally change `ssh_port` (default 2222)
5. Restart the server

On first start with SSH enabled, the server generates an Ed25519 host key and
saves it to `xmodem_ssh_host_key` in the working directory. This key is reused
on subsequent starts so that clients can verify the server's identity.

### Connecting

```sh
ssh <username>@<server-ip> -p 2222
```

After authenticating, you are presented with the same XMODEM Gateway menu
system as a telnet connection, using ANSI terminal mode. All features (file
transfer, SSH/telnet gateway, browser, AI chat, modem emulator, weather) are
available.

### SSH vs Telnet Credentials

The SSH server has its own username and password (`ssh_username` /
`ssh_password`), independent of the telnet credentials (`username` /
`password`). When `xmodem.conf` is first created, both sets default to the same
values (`admin` / `changeme`). After that, each set can be changed
independently.

**Note:** SSH credentials in `xmodem.conf` are stored in plaintext. While the
SSH connection itself is encrypted, the config file is not. Protect it with
appropriate file permissions.

## SSH Gateway

The SSH Gateway allows you to connect through the server to a remote SSH host.
This is useful for accessing SSH servers from terminals that only support telnet
(such as a Commodore 64).

1. From the main menu, press **S** (SSH Gateway)
2. Press **S** to start a connection
3. Enter the remote host, port (default 22), username, and password
4. Once connected, you have a full interactive shell on the remote server
5. Press **Ctrl+]** to disconnect from the SSH session

The server acts as a proxy between your telnet client and the remote SSH server.
All input is forwarded to the SSH session, and all output is sent back to your
terminal. Telnet line-ending conventions (CR+LF, CR+NUL) are automatically
normalized to bare CR for SSH compatibility.

For PETSCII and ASCII terminals, ANSI escape sequences from the remote host are
automatically stripped, and text is converted to the appropriate encoding. ANSI
terminals receive the raw output unmodified. The PTY size is set to 40x25 for
PETSCII and 80x24 for ANSI/ASCII terminals.

## Telnet Gateway

The Telnet Gateway connects through the server to a remote telnet host. This is
useful for accessing BBS systems or other telnet services from retro terminals.

1. From the main menu, press **T** (Telnet Gateway)
2. Enter the remote host and port (default 23)
3. Once connected, all input and output is proxied between your terminal and the
   remote server
4. Press **Ctrl+]** to disconnect

For PETSCII and ASCII terminals, ANSI escape sequences from the remote host are
automatically filtered.

## Modem Emulator

The modem emulator provides Hayes AT command emulation on a physical serial
port. This allows retro hardware (Commodore 64, CP/M machines, etc.) to connect
to the gateway and to remote telnet hosts using a serial connection and standard
modem commands.

### Setting Up

1. From the main menu on a telnet session, press **M** (Modem Emulator)
2. Press **E** to enable the emulator
3. Press **P** to select a serial port (auto-detected)
4. Configure baud rate, data bits, parity, stop bits, and flow control as needed
5. Press **Q** to apply -- settings take effect immediately (no restart needed)

Or edit `xmodem.conf` directly and restart the server.

### Supported AT Commands

| Command | Action |
|---------|--------|
| `AT`    | OK (attention) |
| `ATZ`   | Reset modem (echo on, verbose on, quiet off) |
| `AT&F`  | Factory defaults (same as ATZ) |
| `ATE0` / `ATE1` | Echo off / on |
| `ATV0` / `ATV1` | Numeric / verbose result codes |
| `ATQ0` / `ATQ1` | Result codes on / quiet mode (suppress results) |
| `ATI`   | Show modem identification |
| `ATH`   | Hang up (close any active connection) |
| `ATA`   | Answer (returns NO CARRIER — no incoming calls) |
| `ATO`   | Return to online mode (resume after `+++` escape) |
| `ATDT xmodem-gateway` | Connect to this gateway's menus |
| `ATDT host:port` | Dial a remote telnet host |
| `+++`   | Return to command mode (with 1-second guard time) |

**Result codes:** In verbose mode (default), results are text (`OK`, `CONNECT`,
`NO CARRIER`, `ERROR`). In numeric mode (`ATV0`), results are digits (`0`, `1`,
`3`, `4`). Quiet mode (`ATQ1`) suppresses all result codes.

### Serial Safety

### Escaping and Resuming

The `+++` escape sequence returns to command mode while keeping the connection
alive. Type `ATO` to resume the connection, or `ATH` to hang up. This follows
standard Hayes modem behavior: one second of silence, then `+++`, then another
second of silence.

### Serial Safety

When changing serial port parameters from a serial session, the server asks
for confirmation. If there is no response within 60 seconds (e.g., because the
terminal settings no longer match), the settings are automatically reverted.
This prevents lockout when accidentally misconfiguring the serial port.

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

The last-used zip code is saved to `xmodem.conf` so it becomes the default
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

## License

All rights reserved.
