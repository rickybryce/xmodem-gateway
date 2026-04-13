# XMODEM Gateway

A telnet-based XMODEM file transfer server, SSH gateway, Hayes-compatible modem
emulator for serial-attached retro hardware, text-mode web browser, and AI chat
client written in Rust. Supports PETSCII (Commodore 64), ANSI, and ASCII
terminals. Designed for local network use with retro and modern terminal clients.

**[User Manual](http://telnetbible.com/xmodem-gateway/index.html)**

Once you run the server on your PC, you can telnet to that server from anywhere 
on your network (allow firewall port 2323).  Example:  ATDT 192.168.1.160:2323

This program also serves as a modem emulator.  For an Altairduino PRO, connect 
directly to the altairduino, and set your modem port to be 2SIO2. (A6/A7 on 
mine).  Remember, you can configure the serial ports by pressing stop and aux1
up.

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
(`security_enabled = true` in `xmodem.conf`) and set a strong username and
password. Even with security enabled, running this software on a public network
is **not recommended** — telnet credentials are transmitted in cleartext and can
be intercepted. Use the SSH interface for any non-local access.

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

## GUI Configuration Editor

When `enable_console = true` (the default), a graphical configuration window
opens on startup. The GUI provides:

- **Live console output** -- server log messages stream in the bottom panel
- **Configuration editing** -- all `xmodem.conf` settings can be changed and
  saved without editing the file by hand
- **Serial port auto-detection** -- the Serial Modem section lists detected
  serial ports in a dropdown; click the refresh button to re-scan
- **User Manual button** -- opens the PDF user manual on GitHub in your browser
- **Save and Restart Server** -- writes changes to `xmodem.conf` and restarts
  the server so all changes (including security, ports, and credentials) take
  effect immediately

The GUI window closes automatically when the server receives a shutdown signal
(Ctrl+C, SIGTERM, SIGHUP) or when the Save and Restart Server button is
clicked (the GUI reopens after the restart completes). Closing the GUI window
does **not** stop the server -- it continues running headless until a shutdown
signal is received.

To disable the GUI, set `enable_console = false` in `xmodem.conf` or uncheck
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
- **M** Modem Emulator -- serial port selection and parameters
- **S** Server Configuration -- enable/disable telnet and SSH, set ports
- **X** XMODEM Settings -- transfer directory, timeouts, retry limit
- **O** Other Settings -- AI API key, browser homepage, weather zip, verbose
  logging, GUI on startup
- **R** Reset Defaults -- restore all settings to factory defaults

All settings are persisted to `xmodem.conf` automatically. You can also edit
`xmodem.conf` by hand. All options:

```ini
# Telnet server: set to false to disable (SSH-only mode)
telnet_enabled = true

# Telnet server port
telnet_port = 2323

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

# Verbose logging: set to true for detailed XMODEM protocol diagnostics
verbose = false

# XMODEM protocol timeouts
xmodem_negotiation_timeout = 45
xmodem_block_timeout = 20
xmodem_max_retries = 10

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
serial_s_regs = 5,0,43,13,10,8,2,50,2,6,14,95,50

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
(**C** > **E** Security) or edit `xmodem.conf` by hand:

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
3. Set the key via Configuration > Other Settings > **A** (Set AI API key), or
   open `xmodem.conf` and set: `groq_api_key = gsk_your_key_here`
4. Restart the server

If no API key is configured, selecting AI Chat from the menu will display
instructions on how to obtain one.

### Setting Up the Browser Homepage

The browser loads `http://telnetbible.com` by default. To change it, use
Configuration > Other Settings > **B** (Set browser homepage), or edit
`xmodem.conf`:

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

After detection, the server asks whether to enable color. The user must press
Y or N to continue; no default is applied.

## Transferring Files

### Uploading a File to the Server

1. Connect via telnet and navigate to **F** (File Transfer)
2. Press **U** (Upload)
3. Enter a filename (letters, numbers, dots, hyphens, underscores only; max 64
   characters; cannot start with a dot, cannot contain `..`, must include at
   least one letter or digit)
4. The server displays "Begin XMODEM send now" and waits up to 45 seconds
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
4. The server displays "Start XMODEM receive now" and waits up to 45 seconds
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

## SSH Server

The SSH server provides encrypted access to the same gateway menus and features
available over telnet. This is useful when connecting from modern clients where
encryption is preferred over plaintext telnet.

### Enabling the SSH Server

Use Configuration > Server Configuration to toggle SSH and set the port, and
Configuration > Security to set SSH credentials. Or edit `xmodem.conf` by hand:

1. Set `ssh_enabled = true`
2. Change `ssh_username` and `ssh_password` to your desired credentials
3. Optionally change `ssh_port` (default 2222)
4. Restart the server

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
2. Enter the remote host, port (default 22), username, and password
3. Once connected, you have a full interactive shell on the remote server
4. Press **ESC** twice to disconnect from the SSH session

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
4. Press **ESC** twice to disconnect

For PETSCII and ASCII terminals, ANSI escape sequences from the remote host are
automatically filtered.

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

Or edit `xmodem.conf` directly and restart the server.

### Supported AT Commands

| Command | Action |
|---------|--------|
| `AT`    | OK (attention) |
| `AT?`   | Show AT command help |
| `ATZ`   | Reset modem to stored settings (saved by AT&W) |
| `AT&F`  | Reset modem to factory defaults |
| `AT&W`  | Save current settings (echo, verbose, quiet, S-registers) to config |
| `AT&V`  | Display current modem configuration |
| `ATE0` / `ATE1` | Echo off / on |
| `ATV0` / `ATV1` | Numeric / verbose result codes |
| `ATQ0` / `ATQ1` | Result codes on / quiet mode (suppress results) |
| `ATI`   | Show modem identification |
| `ATH`   | Hang up (close any active connection) |
| `ATA`   | Answer incoming ring |
| `ATO`   | Return to online mode (resume after `+++` escape) |
| `ATS?`  | Show S-register help |
| `ATS`*n*`?` | Query S-register *n* (returns 3-digit value) |
| `ATS`*n*`=`*v* | Set S-register *n* to value *v* (0–255) |
| `ATDL`  | Redial last number |
| `ATDT xmodem-gateway` | Connect to this gateway's menus |
| `ATDT host:port` | Dial a remote telnet host (commas in dial string are stripped) |
| `ATDP host:port` | Pulse dial (same as ATDT — no distinction for TCP) |
| `+++`   | Return to command mode (with guard time from S12) |

**Result codes:** In verbose mode (default), results are text (`OK`, `CONNECT`,
`NO CARRIER`, `ERROR`). In numeric mode (`ATV0`), results are digits (`0`, `1`,
`3`, `4`). Quiet mode (`ATQ1`) suppresses all result codes.

**S-registers:** Query with `ATSn?`, set with `ATSn=v`, or type `ATS?` for help.
`AT&W` saves all registers to `xmodem.conf`; `ATZ` restores saved values;
`AT&F` resets to factory defaults.

| Register | Default | Description |
|----------|---------|-------------|
| S0  | 5   | Auto-answer ring count (0 = disabled) |
| S1  | 0   | Ring counter (current) |
| S2  | 43  | Escape character (43 = `+`) |
| S3  | 13  | Carriage return character |
| S4  | 10  | Line feed character |
| S5  | 8   | Backspace character |
| S6  | 2   | Wait for dial tone (seconds) |
| S7  | 50  | Wait for carrier (seconds) |
| S8  | 2   | Comma pause time (seconds) |
| S9  | 6   | Carrier detect response time (1/10s) |
| S10 | 14  | Carrier loss disconnect time (1/10s) |
| S11 | 95  | DTMF tone duration (milliseconds) |
| S12 | 50  | Escape guard time (1/50s; 50 = 1 second) |

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
XMODEM Gateway main menu, just as if it had dialed in with
`ATDT xmodem-gateway`. The serial device can also answer manually with `ATA`
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

A built-in entry maps **1001000** to the local XMODEM Gateway menu (equivalent
to `ATDT xmodem-gateway`). This entry cannot be deleted.

Mappings are stored in `dialup.conf` (created automatically on first access
with a default starter entry). Phone numbers are matched by digits only --
formatting characters like dashes, spaces, and parentheses are ignored, so
`555-1234` and `5551234` are treated as the same number.

If a dialed number has no mapping, the modem returns `NO CARRIER`. You can
still dial hostnames and `host:port` targets directly -- mappings only apply
when the dial string looks like a phone number (digits and formatting only, no
letters or dots).

### Limitations

This is a software modem emulator, not a real modem. It does not control
RS-232 hardware signal pins. Specifically:

- **DCD (Data Carrier Detect, pin 1)** -- A real modem asserts DCD when a
  carrier signal is established with the remote modem. This emulator cannot
  drive DCD, so the serial device has no hardware indication that a connection
  is active.
- **RI (Ring Indicator, pin 9)** -- A real modem asserts RI when an incoming
  call is ringing. The ring emulator sends `RING` result codes over the serial
  data line, but the RI pin is never driven.
- **DSR (Data Set Ready, pin 6)** -- A real modem asserts DSR when powered on
  and ready. This emulator does not control DSR.
- **DTR (Data Terminal Ready, pin 4)** -- A real modem monitors DTR from the
  terminal to detect hangup requests. This emulator does not read DTR; use the
  `ATH` command or `+++` escape to hang up instead.
- **CTS/RTS (Clear to Send / Request to Send, pins 8/7)** -- Hardware flow
  control is handled by the serial port driver when `serial_flowcontrol` is set
  to `hardware`, but the emulator itself does not manipulate these pins for
  modem state signaling.

Most retro terminal software works fine without these signals, especially when
configured to ignore DCD (sometimes labeled "Force DTR" or "Ignore Carrier" in
the terminal program settings). If your software requires DCD to be asserted
before it will communicate, check its configuration for an option to disable
carrier detection.

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

Portions of this project were developed with the assistance of AI tools 
including Claude Code.

## License

This project is licensed under the [GNU General Public License v3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html) (GPL-3.0-or-later).
