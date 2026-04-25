//! ZMODEM Protocol Module
//!
//! Implements the core ZMODEM file transfer protocol (Chuck Forsberg,
//! 1988) as used by lrzsz, SyncTerm, HyperTerminal, etc.  Covers the
//! single-file send and receive paths needed by the gateway.
//!
//! Design notes:
//! - Stop-and-wait flow control (window size 0) using ZCRCW data
//!   subpackets.  Slower than streaming but vastly simpler and very
//!   widely interoperable.
//! - CRC-16 (poly 0x1021, same as XMODEM CRC) is used by default.  The
//!   receiver advertises CRC-32 capability so we can read either flavour
//!   of incoming data subpacket; our outgoing data always uses CRC-16.
//! - Telnet NVT awareness matches `xmodem.rs`: the raw I/O layer handles
//!   IAC escaping and CR-NUL stuffing.  ZDLE escaping is layered above.
//! - No resume, no compression, no batch mode — one file per session.
//!
//! Public surface (used by `telnet.rs`):
//! - [`zmodem_receive`] — read a single file from the peer (upload)
//! - [`zmodem_send`] — send a single file to the peer (download)

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config;
use crate::logger::glog;

// ─── Wire constants ──────────────────────────────────────────
const ZPAD: u8 = b'*';          // 0x2A, frame padding
const ZDLE: u8 = 0x18;          // ZMODEM escape (same byte as CAN)
#[allow(dead_code)]
const ZDLEE: u8 = 0x58;         // ZDLE ^ 0x40, used to represent a data ZDLE
const ZBIN: u8 = b'A';          // binary header with CRC-16
const ZHEX: u8 = b'B';          // hex header with CRC-16
const ZBIN32: u8 = b'C';        // binary header with CRC-32

// Data-subpacket terminators.  Each is preceded by ZDLE.  The terminator
// byte itself is part of the CRC payload; the ZDLE is not.
const ZCRCE: u8 = b'h';         // end-of-frame, no more data this frame
const ZCRCG: u8 = b'i';         // more data, streaming (no ACK)
const ZCRCQ: u8 = b'j';         // more data, ACK required
const ZCRCW: u8 = b'k';         // more data next frame, ACK required

// Frame types
const ZRQINIT: u8 = 0x00;
const ZRINIT: u8 = 0x01;
#[allow(dead_code)]
const ZSINIT: u8 = 0x02;
const ZACK: u8 = 0x03;
const ZFILE: u8 = 0x04;
const ZSKIP: u8 = 0x05;
const ZNAK: u8 = 0x06;
const ZABORT: u8 = 0x07;
const ZFIN: u8 = 0x08;
const ZRPOS: u8 = 0x09;
const ZDATA: u8 = 0x0A;
const ZEOF: u8 = 0x0B;
#[allow(dead_code)]
const ZFERR: u8 = 0x0C;
#[allow(dead_code)]
const ZCAN: u8 = 0x10;

// ZRINIT capability flags (ZF0 byte of the ZRINIT header)
const CANFDX: u8 = 0x01;        // full-duplex link
const CANOVIO: u8 = 0x02;       // can overlap I/O
const CANFC32: u8 = 0x20;       // can receive CRC-32 frames

// Telnet protocol bytes (same as xmodem.rs; duplicated to keep the
// modules decoupled).
const IAC: u8 = 0xFF;
const SB: u8 = 250;
const SE: u8 = 240;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO_CMD: u8 = 253;
const DONT: u8 = 254;

// Limits
const MAX_FILE_SIZE: u64 = 8 * 1024 * 1024;
const SUBPACKET_DATA_SIZE: usize = 1024;
const MAX_SUBPACKET_DATA: usize = 8192;
// Protocol timeouts and retry caps are no longer compile-time constants —
// they're read from `config::get_config()` so the operator can tune them
// at runtime through the GUI "More..." popup and the telnet
// `File Transfer > ZMODEM Settings` menu (see `config.rs` for defaults).

// =============================================================================
// CRC-16 (CCITT, polynomial 0x1021, seed 0 — same as XMODEM/YMODEM CRC)
// =============================================================================

pub(crate) fn crc16(data: &[u8]) -> u16 {
    crc16_update(0, data)
}

/// CRC-16 update from a running state.  Lets `build_subpacket` compute
/// the CRC over `data || [end_marker]` without allocating a temporary
/// concatenation — saves ~1 KB per subpacket on large transfers.
fn crc16_update(mut crc: u16, data: &[u8]) -> u16 {
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// =============================================================================
// CRC-32 (IEEE reflected, poly 0xEDB88320, seed 0xFFFFFFFF, final XOR)
// =============================================================================

pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let lsb = crc & 1;
            crc >>= 1;
            if lsb != 0 {
                crc ^= 0xEDB8_8320;
            }
        }
    }
    !crc
}

// =============================================================================
// ZDLE escape layer
// =============================================================================

/// Bytes that must be ZDLE-escaped on the wire.  Covers ZDLE itself plus
/// the flow-control bytes that terminals/modems may swallow.
fn needs_zdle_escape(b: u8) -> bool {
    matches!(
        b,
        ZDLE | 0x10 | 0x11 | 0x13 | 0x0D | 0x8D | 0x90 | 0x91 | 0x93
    )
}

/// Append `b` to `out`, ZDLE-escaping it if required.
fn push_escaped(out: &mut Vec<u8>, b: u8) {
    if needs_zdle_escape(b) {
        out.push(ZDLE);
        out.push(b ^ 0x40);
    } else {
        out.push(b);
    }
}

/// Lowercase-hex alphabet used by hex headers (Forsberg spec says
/// lowercase; some receivers accept both but we emit lowercase).
fn hex_digit(v: u8) -> u8 {
    let v = v & 0x0F;
    if v < 10 {
        b'0' + v
    } else {
        b'a' + (v - 10)
    }
}

fn hex_to_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(10 + c - b'a'),
        b'A'..=b'F' => Some(10 + c - b'A'),
        _ => None,
    }
}

// =============================================================================
// Header encoding
// =============================================================================

/// Build a hex-encoded ZMODEM header.  These are the easiest for the
/// peer to parse — pure ASCII, CR-LF terminated, and commonly used for
/// control frames (ZRINIT, ZRPOS, ZEOF, ZFIN, ZACK).
///
/// `data` is `[P0 P1 P2 P3]`; callers pack frame-specific values into
/// those four bytes.
fn build_hex_header(frame: u8, data: [u8; 4]) -> Vec<u8> {
    let payload = [frame, data[0], data[1], data[2], data[3]];
    let crc = crc16(&payload);

    let mut buf = Vec::with_capacity(20);
    buf.push(ZPAD);
    buf.push(ZPAD);
    buf.push(ZDLE);
    buf.push(ZHEX);
    for &b in &payload {
        buf.push(hex_digit(b >> 4));
        buf.push(hex_digit(b));
    }
    buf.push(hex_digit((crc >> 12) as u8));
    buf.push(hex_digit((crc >> 8) as u8));
    buf.push(hex_digit((crc >> 4) as u8));
    buf.push(hex_digit(crc as u8));
    buf.push(b'\r');
    buf.push(b'\n');
    // Per spec, XON is appended after a hex frame unless the frame is
    // ZACK or ZFIN — those need to stay quiet so the peer can continue.
    if frame != ZACK && frame != ZFIN {
        buf.push(0x11); // XON
    }
    buf
}

/// Build a binary-16 ZMODEM header (ZDLE 'A').  Used for ZFILE and
/// ZDATA where a hex header would be clumsy given the data subpacket
/// that follows on the same stream.
fn build_bin16_header(frame: u8, data: [u8; 4]) -> Vec<u8> {
    let payload = [frame, data[0], data[1], data[2], data[3]];
    let crc = crc16(&payload);

    let mut buf = Vec::with_capacity(16);
    buf.push(ZPAD);
    buf.push(ZDLE);
    buf.push(ZBIN);
    for &b in &payload {
        push_escaped(&mut buf, b);
    }
    push_escaped(&mut buf, (crc >> 8) as u8);
    push_escaped(&mut buf, crc as u8);
    buf
}

/// Build a data subpacket body: `data` (ZDLE-escaped) followed by
/// `ZDLE <end_marker> <CRC>`.  The end marker is included in the CRC;
/// the ZDLE prefix is not.
///
/// Uses CRC-16; the enclosing frame type (binary16 vs binary32)
/// determines which CRC width the peer expects.  Our sender emits
/// binary16 frames exclusively, so CRC-16 is always correct here.
fn build_subpacket(data: &[u8], end_marker: u8) -> Vec<u8> {
    // CRC is computed over `data || [end_marker]`.  Avoid the
    // temporary concatenation by folding the end marker into the
    // running CRC state after hashing the data slice.
    let crc = crc16_update(crc16(data), &[end_marker]);

    let mut buf = Vec::with_capacity(data.len() + 6);
    for &b in data {
        push_escaped(&mut buf, b);
    }
    buf.push(ZDLE);
    buf.push(end_marker);
    push_escaped(&mut buf, (crc >> 8) as u8);
    push_escaped(&mut buf, crc as u8);
    buf
}

// =============================================================================
// Decoded header
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
enum CrcKind {
    Crc16,
    Crc32,
}

#[derive(Debug, Clone, Copy)]
struct ZHeader {
    frame: u8,
    data: [u8; 4],
    /// Which CRC width the subsequent data subpackets (if any) will use.
    /// Hex headers don't carry data so this is irrelevant; for binary
    /// headers the frame-indicator byte determines it.
    crc_kind: CrcKind,
}

impl ZHeader {
    /// Interpret `data` as a little-endian 32-bit position/length.  Used
    /// for ZRPOS, ZEOF, ZDATA, ZFILE-size (within the block-0 subpacket,
    /// not here).
    fn position(&self) -> u32 {
        u32::from_le_bytes(self.data)
    }
}

// =============================================================================
// Raw I/O (telnet NVT aware) — parallel to xmodem.rs helpers
// =============================================================================

#[derive(Default)]
struct ReadState {
    pushback: Option<u8>,
}

async fn raw_read_byte(
    reader: &mut (impl AsyncRead + Unpin),
    is_tcp: bool,
) -> Result<u8, String> {
    let mut buf = [0u8; 1];
    loop {
        reader
            .read_exact(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        if is_tcp && buf[0] == IAC {
            reader
                .read_exact(&mut buf)
                .await
                .map_err(|e| e.to_string())?;
            if buf[0] == IAC {
                return Ok(IAC);
            }
            consume_telnet_command(reader, buf[0]).await?;
        } else {
            return Ok(buf[0]);
        }
    }
}

async fn consume_telnet_command(
    reader: &mut (impl AsyncRead + Unpin),
    command: u8,
) -> Result<(), String> {
    let mut buf = [0u8; 1];
    match command {
        SB => {
            let sb_result = tokio::time::timeout(tokio::time::Duration::from_secs(5), async {
                loop {
                    reader
                        .read_exact(&mut buf)
                        .await
                        .map_err(|e| e.to_string())?;
                    if buf[0] == IAC {
                        reader
                            .read_exact(&mut buf)
                            .await
                            .map_err(|e| e.to_string())?;
                        if buf[0] == SE {
                            break;
                        }
                    }
                }
                Ok::<(), String>(())
            })
            .await;
            match sb_result {
                Err(_) => return Err("Telnet subnegotiation timed out".into()),
                Ok(r) => r?,
            }
        }
        WILL | WONT | DO_CMD | DONT => {
            reader
                .read_exact(&mut buf)
                .await
                .map_err(|e| e.to_string())?;
        }
        _ => {}
    }
    Ok(())
}

async fn nvt_read_byte(
    reader: &mut (impl AsyncRead + Unpin),
    is_tcp: bool,
    state: &mut ReadState,
) -> Result<u8, String> {
    if let Some(b) = state.pushback.take() {
        return Ok(b);
    }
    let byte = raw_read_byte(reader, is_tcp).await?;
    if is_tcp && byte == 0x0D {
        let next = raw_read_byte(reader, is_tcp).await?;
        if next != 0x00 {
            state.pushback = Some(next);
        }
    }
    Ok(byte)
}

async fn raw_write_bytes(
    writer: &mut (impl AsyncWrite + Unpin),
    data: &[u8],
    is_tcp: bool,
) -> Result<(), String> {
    if is_tcp {
        let mut buf = Vec::with_capacity(data.len() + 8);
        for &b in data {
            if b == IAC {
                buf.push(IAC);
                buf.push(IAC);
            } else if b == 0x0D {
                buf.push(0x0D);
                buf.push(0x00);
            } else {
                buf.push(b);
            }
        }
        writer.write_all(&buf).await.map_err(|e| e.to_string())?;
        writer.flush().await.map_err(|e| e.to_string())?;
    } else {
        writer.write_all(data).await.map_err(|e| e.to_string())?;
        writer.flush().await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

// =============================================================================
// Header decoder
// =============================================================================

/// Read one ZMODEM header from the wire.  Scans for the ZPAD sync,
/// dispatches on the frame-indicator byte (ZBIN/ZHEX/ZBIN32), validates
/// the CRC, and returns the decoded header.
async fn read_header(
    reader: &mut (impl AsyncRead + Unpin),
    is_tcp: bool,
    state: &mut ReadState,
    verbose: bool,
) -> Result<ZHeader, String> {
    // Scan for the ZPAD + ZDLE + frame-type prologue.  We may encounter
    // extra ZPADs or stray bytes (XON/XOFF, leftover CR/LF from a
    // previous hex header) — discard those until we lock on.
    //
    // Loop is bounded by a generous byte budget so a malicious peer
    // can't force unbounded reads.
    let mut junk_budget: u32 = 4096;
    loop {
        if junk_budget == 0 {
            return Err("ZMODEM: header sync lost".into());
        }
        junk_budget -= 1;

        let b = nvt_read_byte(reader, is_tcp, state).await?;
        if b != ZPAD {
            continue;
        }
        // Consume additional ZPAD if present (hex header has two).
        let mut next = nvt_read_byte(reader, is_tcp, state).await?;
        if next == ZPAD {
            next = nvt_read_byte(reader, is_tcp, state).await?;
        }
        if next != ZDLE {
            continue;
        }
        let kind = nvt_read_byte(reader, is_tcp, state).await?;
        match kind {
            ZHEX => return read_hex_body(reader, is_tcp, state, verbose).await,
            ZBIN => return read_bin16_body(reader, is_tcp, state, verbose).await,
            ZBIN32 => return read_bin32_body(reader, is_tcp, state, verbose).await,
            _ => continue, // resync
        }
    }
}

/// Read one ZDLE-escaped byte.  Returns the unescaped data byte, or
/// `Err` if a subpacket-terminator appeared where a data byte was
/// expected (caller should treat that as corruption).
async fn read_escaped_byte(
    reader: &mut (impl AsyncRead + Unpin),
    is_tcp: bool,
    state: &mut ReadState,
) -> Result<u8, String> {
    let b = nvt_read_byte(reader, is_tcp, state).await?;
    if b != ZDLE {
        return Ok(b);
    }
    let e = nvt_read_byte(reader, is_tcp, state).await?;
    match e {
        ZCRCE | ZCRCG | ZCRCQ | ZCRCW => {
            Err(format!("Unexpected subpacket terminator 0x{:02X}", e))
        }
        _ => Ok(e ^ 0x40),
    }
}

async fn read_bin16_body(
    reader: &mut (impl AsyncRead + Unpin),
    is_tcp: bool,
    state: &mut ReadState,
    verbose: bool,
) -> Result<ZHeader, String> {
    let mut payload = [0u8; 5];
    for slot in payload.iter_mut() {
        *slot = read_escaped_byte(reader, is_tcp, state).await?;
    }
    let crc_hi = read_escaped_byte(reader, is_tcp, state).await?;
    let crc_lo = read_escaped_byte(reader, is_tcp, state).await?;
    let expected = ((crc_hi as u16) << 8) | (crc_lo as u16);
    let actual = crc16(&payload);
    if actual != expected {
        return Err(format!(
            "ZMODEM: binary16 header CRC mismatch (got {:04X}, expected {:04X})",
            actual, expected
        ));
    }
    if verbose {
        glog!(
            "ZMODEM: got binary16 header type=0x{:02X} data={:02X}{:02X}{:02X}{:02X}",
            payload[0], payload[1], payload[2], payload[3], payload[4]
        );
    }
    Ok(ZHeader {
        frame: payload[0],
        data: [payload[1], payload[2], payload[3], payload[4]],
        crc_kind: CrcKind::Crc16,
    })
}

async fn read_bin32_body(
    reader: &mut (impl AsyncRead + Unpin),
    is_tcp: bool,
    state: &mut ReadState,
    verbose: bool,
) -> Result<ZHeader, String> {
    let mut payload = [0u8; 5];
    for slot in payload.iter_mut() {
        *slot = read_escaped_byte(reader, is_tcp, state).await?;
    }
    let mut crc_bytes = [0u8; 4];
    for slot in crc_bytes.iter_mut() {
        *slot = read_escaped_byte(reader, is_tcp, state).await?;
    }
    let expected = u32::from_le_bytes(crc_bytes);
    let actual = crc32(&payload);
    if actual != expected {
        return Err(format!(
            "ZMODEM: binary32 header CRC mismatch (got {:08X}, expected {:08X})",
            actual, expected
        ));
    }
    if verbose {
        glog!(
            "ZMODEM: got binary32 header type=0x{:02X} data={:02X}{:02X}{:02X}{:02X}",
            payload[0], payload[1], payload[2], payload[3], payload[4]
        );
    }
    Ok(ZHeader {
        frame: payload[0],
        data: [payload[1], payload[2], payload[3], payload[4]],
        crc_kind: CrcKind::Crc32,
    })
}

async fn read_hex_body(
    reader: &mut (impl AsyncRead + Unpin),
    is_tcp: bool,
    state: &mut ReadState,
    verbose: bool,
) -> Result<ZHeader, String> {
    // 5 payload bytes + 2 CRC bytes = 14 hex characters.
    let mut raw = [0u8; 7];
    for slot in raw.iter_mut() {
        let hi = nvt_read_byte(reader, is_tcp, state).await?;
        let lo = nvt_read_byte(reader, is_tcp, state).await?;
        let hi = hex_to_nibble(hi).ok_or_else(|| "ZMODEM: bad hex digit".to_string())?;
        let lo = hex_to_nibble(lo).ok_or_else(|| "ZMODEM: bad hex digit".to_string())?;
        *slot = (hi << 4) | lo;
    }
    let payload = &raw[..5];
    let expected = ((raw[5] as u16) << 8) | (raw[6] as u16);
    let actual = crc16(payload);
    if actual != expected {
        return Err(format!(
            "ZMODEM: hex header CRC mismatch (got {:04X}, expected {:04X})",
            actual, expected
        ));
    }
    // Swallow the trailing CR LF (and optional XON) so the stream lines
    // up for the next frame.  Up to 3 trailing bytes per spec.
    for _ in 0..3 {
        let next_res =
            tokio::time::timeout(tokio::time::Duration::from_millis(200), async {
                nvt_read_byte(reader, is_tcp, state).await
            })
            .await;
        match next_res {
            Ok(Ok(b)) if b == 0x0A || b == 0x8A || b == 0x0D || b == 0x11 => continue,
            Ok(Ok(b)) => {
                // Unexpected byte — push it back for the next header reader.
                state.pushback = Some(b);
                break;
            }
            // Timeout or I/O error — don't block forever, let the caller
            // handle any downstream issue.
            _ => break,
        }
    }
    if verbose {
        glog!(
            "ZMODEM: got hex header type=0x{:02X} data={:02X}{:02X}{:02X}{:02X}",
            raw[0], raw[1], raw[2], raw[3], raw[4]
        );
    }
    Ok(ZHeader {
        frame: raw[0],
        data: [raw[1], raw[2], raw[3], raw[4]],
        crc_kind: CrcKind::Crc16,
    })
}

/// Outcome of a single data-subpacket read.
struct Subpacket {
    data: Vec<u8>,
    end_marker: u8,
}

/// Read one data subpacket that follows a binary header.  Unescapes
/// bytes as they arrive, stopping at the first ZDLE+end-marker.  CRC is
/// validated against the width declared by the enclosing header.
async fn read_subpacket(
    reader: &mut (impl AsyncRead + Unpin),
    is_tcp: bool,
    state: &mut ReadState,
    crc_kind: CrcKind,
    max_len: usize,
) -> Result<Subpacket, String> {
    let mut data = Vec::with_capacity(SUBPACKET_DATA_SIZE);
    loop {
        if data.len() > max_len {
            return Err("ZMODEM: subpacket exceeds size limit".into());
        }
        let b = nvt_read_byte(reader, is_tcp, state).await?;
        if b != ZDLE {
            data.push(b);
            continue;
        }
        let e = nvt_read_byte(reader, is_tcp, state).await?;
        match e {
            ZCRCE | ZCRCG | ZCRCQ | ZCRCW => {
                // Validate CRC (computed over data + end marker).  Push
                // the end marker onto `data` for the CRC pass then pop
                // it back off — avoids cloning the whole subpacket on
                // every validation, which can be megabytes of churn
                // across a large transfer.
                data.push(e);
                let crc_result = match crc_kind {
                    CrcKind::Crc16 => {
                        let hi = read_escaped_byte(reader, is_tcp, state).await?;
                        let lo = read_escaped_byte(reader, is_tcp, state).await?;
                        let expected = ((hi as u16) << 8) | (lo as u16);
                        let actual = crc16(&data);
                        if actual != expected {
                            Err(format!(
                                "ZMODEM: subpacket CRC-16 mismatch (got {:04X}, expected {:04X})",
                                actual, expected
                            ))
                        } else {
                            Ok(())
                        }
                    }
                    CrcKind::Crc32 => {
                        let mut crc_bytes = [0u8; 4];
                        for slot in crc_bytes.iter_mut() {
                            *slot = read_escaped_byte(reader, is_tcp, state).await?;
                        }
                        let expected = u32::from_le_bytes(crc_bytes);
                        let actual = crc32(&data);
                        if actual != expected {
                            Err(format!(
                                "ZMODEM: subpacket CRC-32 mismatch (got {:08X}, expected {:08X})",
                                actual, expected
                            ))
                        } else {
                            Ok(())
                        }
                    }
                };
                data.pop();
                crc_result?;
                return Ok(Subpacket { data, end_marker: e });
            }
            _ => {
                data.push(e ^ 0x40);
            }
        }
    }
}

// =============================================================================
// Receive (upload: data flows sender → gateway)
// =============================================================================

/// Result of a successful ZMODEM receive — both the received filename
/// (extracted from the ZFILE subpacket) and the raw bytes.
pub(crate) struct ZmodemReceive {
    /// Filename advertised by the sender in the ZFILE header.  For the
    /// first file of a batch the caller typically overrides this with
    /// the user-entered name from the upload prompt; for subsequent
    /// files the caller uses this name directly (after the same path-
    /// validation rules applied to user input).
    pub filename: String,
    pub data: Vec<u8>,
}

/// Receive one or more files via ZMODEM (batch mode, per Forsberg §4).
/// Handshake (for a two-file session as an example):
///   → "rz\r" + ZRINIT
///   ← ZFILE + subpacket(filename\0length\0...)
///   → ZRPOS(0)
///   ← ZDATA(0) + data subpackets
///   ← ZEOF
///   → ZRINIT                 ← ready for next file or ZFIN
///   ← ZFILE + subpacket      ← second file
///   → ZRPOS(0)
///   ← ZDATA(0) + subpackets
///   ← ZEOF
///   → ZRINIT
///   ← ZFIN
///   → ZFIN
///   → "OO"
///
/// Returns one [`ZmodemReceive`] per file the receiver chose to
/// accept.  The `decide` callback runs after each ZFILE header is
/// parsed with `(index, sender_filename, declared_size)`; returning
/// `true` accepts the file (we send ZRPOS(0) and receive the data),
/// `false` rejects it (we send ZSKIP per Forsberg §7 and the sender
/// moves on without transmitting data).  The index counts every ZFILE
/// the sender sent, including files we skipped, so callers can
/// implement "accept file 0, validate files 1.." without maintaining
/// their own counter.
pub(crate) async fn zmodem_receive<F>(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    verbose: bool,
    mut decide: F,
) -> Result<Vec<ZmodemReceive>, String>
where
    F: FnMut(usize, &str, Option<u64>) -> bool,
{
    let mut state = ReadState::default();
    if verbose {
        glog!("ZMODEM recv: starting (is_tcp={})", is_tcp);
    }

    // Emit `rz\r` followed by a ZRINIT.  The `rz\r` prefix is the
    // classic auto-start trigger that several terminal emulators
    // (Qodem, ZOC, MuPuTTY, BBS-era) watch for and use to launch
    // their ZMODEM sender; terminals that don't recognise it see
    // two harmless visible characters before the hex frame.
    //
    // The overall negotiation budget comes from
    // `zmodem_negotiation_timeout` (default 45 s) and only applies
    // until the first ZFILE arrives — once the sender is engaged, the
    // per-frame timeouts take over so a slow sender transmitting a
    // large batch isn't killed by a wall-clock deadline.
    let cfg = config::get_config();
    let negotiation_deadline = tokio::time::Instant::now()
        + tokio::time::Duration::from_secs(cfg.zmodem_negotiation_timeout);
    let negotiation_retry_interval = cfg.zmodem_negotiation_retry_interval;
    raw_write_bytes(writer, b"rz\r", is_tcp).await?;
    send_zrinit(writer, is_tcp, verbose).await?;

    let mut files: Vec<ZmodemReceive> = Vec::new();
    // Count of ZFILE headers the sender sent (accepted + skipped), so
    // the decide callback sees a stable file index and so we can
    // distinguish "no files arrived" (real error) from "all files
    // skipped" (legitimate session outcome).
    let mut zfile_seen: usize = 0;

    loop {
        // Only the first file sees the 45 s negotiation deadline —
        // once we've received at least one file the sender is clearly
        // live, and the per-frame 10 s read timeout below is the
        // relevant bound.
        let deadline_active = files.is_empty();

        let read_res = tokio::time::timeout(
            tokio::time::Duration::from_secs(if deadline_active {
                negotiation_retry_interval
            } else {
                10
            }),
            read_header(reader, is_tcp, &mut state, verbose),
        )
        .await;

        let hdr = match read_res {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                if verbose {
                    glog!("ZMODEM recv: header read error: {}", e);
                }
                if deadline_active
                    && tokio::time::Instant::now() >= negotiation_deadline
                {
                    send_cancel(writer, is_tcp).await.ok();
                    return Err("ZMODEM: no ZFILE received from sender".into());
                }
                if deadline_active {
                    send_zrinit(writer, is_tcp, verbose).await?;
                    continue;
                }
                // Between-files read error: assume peer went away.
                break;
            }
            Err(_) => {
                if deadline_active {
                    if tokio::time::Instant::now() >= negotiation_deadline {
                        send_cancel(writer, is_tcp).await.ok();
                        return Err("ZMODEM: no ZFILE received from sender".into());
                    }
                    if verbose {
                        glog!("ZMODEM recv: header timeout — resending ZRINIT");
                    }
                    send_zrinit(writer, is_tcp, verbose).await?;
                    continue;
                }
                // Between-files: sender didn't send ZFILE or ZFIN in
                // the window.  Treat as end-of-session rather than
                // sitting forever.
                if verbose {
                    glog!(
                        "ZMODEM recv: inter-file timeout after {} file(s)",
                        files.len()
                    );
                }
                break;
            }
        };

        match hdr.frame {
            ZRQINIT => {
                // Stale init or sender still waiting — the timeout
                // branch above handles ZRINIT retransmission.
                if verbose {
                    glog!("ZMODEM recv: saw ZRQINIT, continuing to wait");
                }
                continue;
            }
            ZFILE => {
                let file_index = zfile_seen;
                zfile_seen += 1;
                let decision = receive_one_file(
                    reader,
                    writer,
                    &mut state,
                    hdr.crc_kind,
                    is_tcp,
                    verbose,
                    file_index,
                    &mut decide,
                )
                .await?;
                let accepted = decision.is_some();
                if let Some(rx) = decision {
                    files.push(rx);
                }
                // Per Forsberg §7.4.1 the receiver sends ZRINIT after a
                // file *completes* (post-ZEOF) to signal "ready for
                // next file or ZFIN".  After a ZSKIP the sender already
                // has its "move on" signal — sending a redundant ZRINIT
                // leaves a stray frame in the sender's read buffer that
                // can confuse the next ZFILE or the Phase 5 ZFIN wait.
                if accepted {
                    send_zrinit(writer, is_tcp, verbose).await?;
                }
                continue;
            }
            ZFIN => {
                // Sender announces end of batch.  Mirror the ZFIN and
                // emit the "OO" over-and-out trailer.
                send_zfin(writer, is_tcp, verbose).await?;
                raw_write_bytes(writer, b"OO", is_tcp).await.ok();
                break;
            }
            ZABORT => {
                return Err("ZMODEM: sender aborted".into());
            }
            ZSINIT => {
                // Per Forsberg §11.3: sender announces its escape
                // requirements (TESCCTL bit in ZF0) and its Attn
                // sequence in a small ZDLE-escaped subpacket.  We
                // must drain the subpacket and respond with ZACK,
                // otherwise the sender stalls waiting for our reply.
                // We don't act on the Attn sequence — it's only used
                // by senders that want the receiver to interrupt them
                // mid-stream, which isn't part of our use case.
                let _ = read_subpacket(
                    reader,
                    is_tcp,
                    &mut state,
                    hdr.crc_kind,
                    32, // ZATTNLEN cap per spec
                )
                .await;
                send_zack(writer, is_tcp, 1, verbose).await?;
                if verbose {
                    glog!("ZMODEM recv: ACKed ZSINIT (escape-mode negotiation)");
                }
                continue;
            }
            other => {
                if verbose {
                    glog!("ZMODEM recv: ignoring header type 0x{:02X}", other);
                }
                continue;
            }
        }
    }

    if zfile_seen == 0 {
        return Err("ZMODEM: session ended with no files received".into());
    }
    if verbose {
        glog!(
            "ZMODEM recv: batch complete, {} accepted / {} total ZFILE(s)",
            files.len(),
            zfile_seen
        );
    }
    Ok(files)
}

/// Receive the body of a single file after its ZFILE header has already
/// been read.  Reads the ZFILE subpacket (filename, declared size) and
/// consults the caller's decide callback: if the caller accepts the
/// file we send ZRPOS(0) and read ZDATA + ZEOF as normal, returning
/// the decoded file; if the caller rejects, we send ZSKIP per
/// Forsberg §7 and return `Ok(None)`.  Does NOT send the post-ZEOF
/// ZRINIT — the caller does that only on acceptance.
#[allow(clippy::too_many_arguments)]
async fn receive_one_file<F>(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    state: &mut ReadState,
    crc_kind: CrcKind,
    is_tcp: bool,
    verbose: bool,
    file_index: usize,
    decide: &mut F,
) -> Result<Option<ZmodemReceive>, String>
where
    F: FnMut(usize, &str, Option<u64>) -> bool,
{
    let cfg = config::get_config();
    let frame_timeout = cfg.zmodem_frame_timeout;
    let max_retries = cfg.zmodem_max_retries;

    // Read ZFILE subpacket: filename \0 size [modtime [mode [...]]] \0
    let sub = read_subpacket(reader, is_tcp, state, crc_kind, MAX_SUBPACKET_DATA).await?;
    let (filename, expected_size) = parse_zfile_info(&sub.data)?;
    if verbose {
        glog!(
            "ZMODEM recv: ZFILE #{} filename='{}' size={}",
            file_index,
            filename,
            expected_size.unwrap_or(0)
        );
    }
    if let Some(sz) = expected_size {
        if sz > MAX_FILE_SIZE {
            // File too big — send ZSKIP rather than ZABORT so batch
            // senders can keep going with smaller files after us.
            if verbose {
                glog!(
                    "ZMODEM recv: file too large ({} bytes, limit {}), sending ZSKIP",
                    sz, MAX_FILE_SIZE
                );
            }
            send_zskip(writer, is_tcp, verbose).await?;
            return Ok(None);
        }
    }

    // Consult the caller.  The decide callback is sync; if it decides
    // to reject, we emit ZSKIP (which sz/rz treat as "move to next
    // file in batch") and return None to signal the skip to the main
    // loop.
    if !decide(file_index, &filename, expected_size) {
        if verbose {
            glog!("ZMODEM recv: decide() rejected '{}', sending ZSKIP", filename);
        }
        send_zskip(writer, is_tcp, verbose).await?;
        return Ok(None);
    }

    let mut file_data: Vec<u8> = Vec::new();
    let mut expected_pos: u32 = 0;
    let mut zrpos_attempts: u32 = 0;
    // Count of subpackets processed — used to throttle verbose
    // per-subpacket logs the same way `xmodem.rs` throttles block
    // logs (first few + on any error).
    let mut subpackets_seen: u32 = 0;

    // Ask for data starting at offset 0.
    send_zrpos(writer, is_tcp, expected_pos, verbose).await?;

    'data_loop: loop {
        let hdr = match tokio::time::timeout(
            tokio::time::Duration::from_secs(frame_timeout),
            read_header(reader, is_tcp, state, verbose),
        )
        .await
        {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                if verbose {
                    glog!("ZMODEM recv: header read error: {}", e);
                }
                zrpos_attempts += 1;
                if zrpos_attempts >= max_retries {
                    send_cancel(writer, is_tcp).await.ok();
                    return Err("ZMODEM: too many header errors during receive".into());
                }
                send_zrpos(writer, is_tcp, expected_pos, verbose).await?;
                continue;
            }
            Err(_) => {
                send_cancel(writer, is_tcp).await.ok();
                return Err("ZMODEM: timeout waiting for data".into());
            }
        };

        match hdr.frame {
            ZDATA => {
                let offset = hdr.position();
                if offset != expected_pos {
                    if verbose {
                        glog!(
                            "ZMODEM recv: ZDATA offset {} != expected {}, NAKing",
                            offset,
                            expected_pos
                        );
                    }
                    send_zrpos(writer, is_tcp, expected_pos, verbose).await?;
                    continue;
                }
                loop {
                    let sub = match read_subpacket(
                        reader,
                        is_tcp,
                        state,
                        hdr.crc_kind,
                        MAX_SUBPACKET_DATA,
                    )
                    .await
                    {
                        Ok(s) => s,
                        Err(e) => {
                            if verbose {
                                glog!("ZMODEM recv: subpacket error: {}", e);
                            }
                            send_zrpos(writer, is_tcp, expected_pos, verbose).await?;
                            continue 'data_loop;
                        }
                    };
                    subpackets_seen += 1;
                    if verbose && subpackets_seen <= 3 {
                        glog!(
                            "ZMODEM recv: subpacket #{} OK ({} bytes, marker=0x{:02X}, pos={})",
                            subpackets_seen,
                            sub.data.len(),
                            sub.end_marker,
                            expected_pos as usize + sub.data.len()
                        );
                    }
                    file_data.extend_from_slice(&sub.data);
                    expected_pos = expected_pos.saturating_add(sub.data.len() as u32);
                    if file_data.len() as u64 > MAX_FILE_SIZE {
                        send_cancel(writer, is_tcp).await.ok();
                        return Err("ZMODEM: file exceeds size limit".into());
                    }
                    match sub.end_marker {
                        ZCRCG => continue,
                        ZCRCQ => {
                            send_zack(writer, is_tcp, expected_pos, verbose).await?;
                            continue;
                        }
                        ZCRCW => {
                            send_zack(writer, is_tcp, expected_pos, verbose).await?;
                            continue 'data_loop;
                        }
                        ZCRCE => continue 'data_loop,
                        // `read_subpacket` already filters end markers to
                        // the four ZCRC* values; any other byte would
                        // have been returned as an error from that
                        // function before we got here.
                        _ => unreachable!(),
                    }
                }
            }
            ZEOF => {
                let eof_pos = hdr.position();
                if verbose {
                    glog!(
                        "ZMODEM recv: ZEOF at {} (received {} bytes)",
                        eof_pos,
                        file_data.len()
                    );
                }
                if eof_pos as usize != file_data.len() {
                    if verbose {
                        glog!(
                            "ZMODEM recv: ZEOF pos {} != received {}, NAKing",
                            eof_pos,
                            file_data.len()
                        );
                    }
                    send_zrpos(writer, is_tcp, expected_pos, verbose).await?;
                    continue;
                }
                break;
            }
            ZRQINIT => {
                // Sender restarted mid-file — resend ZRINIT and wait
                // for them to come back.
                send_zrinit(writer, is_tcp, verbose).await?;
                continue;
            }
            ZABORT => return Err("ZMODEM: sender aborted".into()),
            other => {
                if verbose {
                    glog!(
                        "ZMODEM recv: unexpected header 0x{:02X} during data phase",
                        other
                    );
                }
                send_zrpos(writer, is_tcp, expected_pos, verbose).await?;
            }
        }
    }

    // Truncate to announced length if the sender provided one.  Handles
    // sub-1024 final subpackets that get padded to the subpacket
    // boundary in some sender implementations.
    if let Some(sz) = expected_size {
        if (file_data.len() as u64) > sz {
            file_data.truncate(sz as usize);
        }
    }

    Ok(Some(ZmodemReceive {
        filename,
        data: file_data,
    }))
}

/// Extract filename and optional declared length from the ZFILE block-0
/// subpacket.  Layout per spec: `<filename>\0<length> <modtime> <mode>
/// <serial> <files-left> <bytes-left>\0` — we only parse filename and
/// length; everything else is ignored.  The length field is decimal
/// ASCII and may be absent on minimal senders.
fn parse_zfile_info(data: &[u8]) -> Result<(String, Option<u64>), String> {
    let nul = data
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "ZMODEM: malformed ZFILE subpacket (no NUL after filename)".to_string())?;
    let filename = std::str::from_utf8(&data[..nul])
        .map_err(|_| "ZMODEM: filename is not valid UTF-8".to_string())?
        .to_string();
    let rest = &data[nul + 1..];
    // Second field is ascii decimal length, optionally followed by
    // space-separated metadata.
    let size = rest
        .split(|&b| b == b' ' || b == 0)
        .find(|s| !s.is_empty())
        .and_then(|s| std::str::from_utf8(s).ok())
        .and_then(|s| s.parse::<u64>().ok());
    Ok((filename, size))
}

// =============================================================================
// Send (download: data flows gateway → receiver)
// =============================================================================

/// Send one file via ZMODEM.  Handshake:
///   → ZRQINIT
///   ← ZRINIT (with capability bits)
///   → ZFILE + subpacket(filename \0 size \0, ZCRCW)
///   ← ZRPOS(0)
///   → ZDATA(0) + subpackets of 1024 bytes each (ZCRCW, ACK-gated) until EOF
///   → ZEOF(length)
///   ← ZRINIT
///   → ZFIN
///   ← ZFIN
///   → "OO"
pub(crate) async fn zmodem_send(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    files: &[(&str, &[u8])],
    is_tcp: bool,
    verbose: bool,
) -> Result<(), String> {
    // Enforce the u32 position-field bound once, up front, for every
    // file in the batch.  The gateway caller's MAX_FILE_SIZE is 8 MB,
    // well under 4 GiB, but documenting the invariant here means
    // later `as u32` casts can't silently truncate if that limit is
    // ever raised.
    for (fname, data) in files {
        if data.len() > u32::MAX as usize {
            return Err(format!(
                "ZMODEM: file '{}' larger than 4 GiB, not supported",
                fname
            ));
        }
    }

    let mut state = ReadState::default();
    if verbose {
        glog!(
            "ZMODEM send: starting batch of {} file(s), is_tcp={}",
            files.len(),
            is_tcp
        );
    }
    let cfg = config::get_config();
    let negotiation_timeout = cfg.zmodem_negotiation_timeout;
    let frame_timeout = cfg.zmodem_frame_timeout;
    let max_retries = cfg.zmodem_max_retries;
    let negotiation_retry_interval = cfg.zmodem_negotiation_retry_interval;

    // ─── Phase 1: ZRQINIT → ZRINIT (once, per session) ──────
    let deadline = tokio::time::Instant::now()
        + tokio::time::Duration::from_secs(negotiation_timeout);
    let mut attempts: u32 = 0;
    loop {
        if tokio::time::Instant::now() >= deadline || attempts >= max_retries {
            return Err("ZMODEM: no ZRINIT from receiver".into());
        }
        send_zrqinit(writer, is_tcp, verbose).await?;
        attempts += 1;

        match tokio::time::timeout(
            tokio::time::Duration::from_secs(negotiation_retry_interval),
            read_header(reader, is_tcp, &mut state, verbose),
        )
        .await
        {
            Ok(Ok(h)) if h.frame == ZRINIT => break,
            Ok(Ok(h)) if h.frame == ZRQINIT => {
                // Receiver also sent a ZRQINIT (non-standard); continue.
                continue;
            }
            Ok(Ok(h)) => {
                if verbose {
                    glog!(
                        "ZMODEM send: unexpected frame 0x{:02X} while awaiting ZRINIT",
                        h.frame
                    );
                }
                continue;
            }
            _ => {
                if verbose {
                    glog!("ZMODEM send: ZRINIT wait timed out, re-sending ZRQINIT");
                }
                continue;
            }
        }
    }

    // ─── Phase 2–4: transmit each file ───────────────────────
    //
    // Per Forsberg §4, a ZMODEM session is a sequence of file
    // transfers:
    //   for each file:
    //     ZFILE + subpacket → ZRPOS (accept) or ZSKIP (skip)
    //     if accepted: ZDATA + subpackets → ZEOF → ZRINIT
    //   after last file: ZFIN → ZFIN → "OO"
    for (filename, data) in files {
        if verbose {
            glog!(
                "ZMODEM send: file '{}' ({} bytes)",
                filename,
                data.len()
            );
        }
        let mut info = Vec::<u8>::new();
        info.extend_from_slice(filename.as_bytes());
        info.push(0);
        let tail = format!("{} 0 0 0 0 {}", data.len(), data.len());
        info.extend_from_slice(tail.as_bytes());
        info.push(0);

        let mut zfile_attempts: u32 = 0;
        let start_pos: u32;
        let mut skipped = false;
        'zfile: loop {
            if zfile_attempts >= max_retries {
                send_cancel(writer, is_tcp).await.ok();
                return Err("ZMODEM: no ZRPOS from receiver".into());
            }
            zfile_attempts += 1;

            let mut frame = build_bin16_header(ZFILE, [0, 0, 0, 0]);
            frame.extend_from_slice(&build_subpacket(&info, ZCRCW));
            raw_write_bytes(writer, &frame, is_tcp).await?;
            if verbose {
                glog!("ZMODEM send: sent ZFILE + subpacket for '{}'", filename);
            }

            // Drain stale ZRINITs queued by the receiver (lrzsz emits
            // multiple at startup before processing our first ZFILE)
            // without retransmitting — every ZFILE we send produces a
            // matching ZRPOS/ZSKIP, and a duplicate would leak into the
            // next file's exchange.  On a true timeout we fall through
            // to the outer loop, which retransmits ZFILE.
            loop {
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(frame_timeout),
                    read_header(reader, is_tcp, &mut state, verbose),
                )
                .await
                {
                    Ok(Ok(h)) if h.frame == ZRPOS => {
                        start_pos = h.position();
                        break 'zfile;
                    }
                    Ok(Ok(h)) if h.frame == ZSKIP => {
                        // Receiver rejects this file (Forsberg §7) —
                        // skip to the next without sending ZDATA/ZEOF.
                        if verbose {
                            glog!(
                                "ZMODEM send: receiver sent ZSKIP for '{}', skipping",
                                filename
                            );
                        }
                        skipped = true;
                        start_pos = 0;
                        break 'zfile;
                    }
                    Ok(Ok(h)) if h.frame == ZRINIT => {
                        if verbose {
                            glog!("ZMODEM send: draining stale ZRINIT after ZFILE");
                        }
                        continue;
                    }
                    Ok(Ok(h)) if h.frame == ZABORT => {
                        return Err("ZMODEM: receiver aborted".into());
                    }
                    Ok(Ok(h)) => {
                        if verbose {
                            glog!(
                                "ZMODEM send: unexpected frame 0x{:02X} while awaiting ZRPOS",
                                h.frame
                            );
                        }
                        continue 'zfile;
                    }
                    _ => continue 'zfile,
                }
            }
        }

        if skipped {
            continue;
        }

        let start_pos = (start_pos as usize).min(data.len());

        // ─── Phase 3: ZDATA + subpackets ─────────────────────
        //
        // For zero-length files there's no ZDATA to send — jump
        // straight to ZEOF once ZRPOS is received.  Emitting an orphan
        // ZDATA header with no subpacket desyncs the receiver.
        let mut pos = start_pos;
        let mut zdata_attempts: u32 = 0;
        let mut subpackets_sent: u32 = 0;
        'send_loop: loop {
            if pos >= data.len() {
                break;
            }
            if zdata_attempts >= max_retries {
                send_cancel(writer, is_tcp).await.ok();
                return Err("ZMODEM: too many retransmissions".into());
            }
            zdata_attempts += 1;

            let hdr = build_bin16_header(ZDATA, (pos as u32).to_le_bytes());
            raw_write_bytes(writer, &hdr, is_tcp).await?;
            if verbose {
                glog!("ZMODEM send: sent ZDATA at offset {}", pos);
            }

            // Mid-frame subpackets use ZCRCQ (ACK required, frame stays
            // open).  The final subpacket uses ZCRCE (frame closes, no
            // ACK) so the peer goes back to reading headers where it
            // will pick up our ZEOF.  Both are spec-compliant per §8.4.
            while pos < data.len() {
                let remaining = data.len() - pos;
                let chunk_len = remaining.min(SUBPACKET_DATA_SIZE);
                let chunk = &data[pos..pos + chunk_len];
                let is_last = pos + chunk_len == data.len();
                let end_marker = if is_last { ZCRCE } else { ZCRCQ };
                let sub = build_subpacket(chunk, end_marker);
                raw_write_bytes(writer, &sub, is_tcp).await?;
                subpackets_sent += 1;
                if verbose && (subpackets_sent <= 3 || zdata_attempts > 1) {
                    glog!(
                        "ZMODEM send: subpacket #{} ({} bytes, marker=0x{:02X}, pos={})",
                        subpackets_sent,
                        chunk_len,
                        end_marker,
                        pos + chunk_len
                    );
                }

                if is_last {
                    break;
                }

                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(frame_timeout),
                    read_header(reader, is_tcp, &mut state, verbose),
                )
                .await
                {
                    Ok(Ok(h)) if h.frame == ZACK => {
                        let ack_pos = h.position() as usize;
                        if ack_pos == pos + chunk_len {
                            pos += chunk_len;
                            continue;
                        }
                        pos = ack_pos.min(data.len());
                        continue 'send_loop;
                    }
                    Ok(Ok(h)) if h.frame == ZRPOS => {
                        pos = (h.position() as usize).min(data.len());
                        continue 'send_loop;
                    }
                    Ok(Ok(h)) if h.frame == ZABORT => {
                        return Err("ZMODEM: receiver aborted".into());
                    }
                    Ok(Ok(h)) if h.frame == ZNAK => {
                        continue 'send_loop;
                    }
                    _ => {
                        continue 'send_loop;
                    }
                }
            }

            break;
        }

        // ─── Phase 4: ZEOF → ZRINIT ──────────────────────────
        let mut zeof_attempts: u32 = 0;
        loop {
            if zeof_attempts >= 5 {
                send_cancel(writer, is_tcp).await.ok();
                return Err("ZMODEM: receiver did not acknowledge ZEOF".into());
            }
            zeof_attempts += 1;
            send_zeof(writer, is_tcp, data.len() as u32, verbose).await?;

            match tokio::time::timeout(
                tokio::time::Duration::from_secs(15),
                read_header(reader, is_tcp, &mut state, verbose),
            )
            .await
            {
                Ok(Ok(h)) if h.frame == ZRINIT => break,
                Ok(Ok(h)) if h.frame == ZRPOS => {
                    // Data got lost — back up and retry from the
                    // requested position.  Safe because ZMODEM
                    // positions are absolute.
                    let mut pos = (h.position() as usize).min(data.len());
                    let hdr = build_bin16_header(ZDATA, (pos as u32).to_le_bytes());
                    raw_write_bytes(writer, &hdr, is_tcp).await?;
                    while pos < data.len() {
                        let chunk_len = (data.len() - pos).min(SUBPACKET_DATA_SIZE);
                        let chunk = &data[pos..pos + chunk_len];
                        let is_last = pos + chunk_len == data.len();
                        let marker = if is_last { ZCRCE } else { ZCRCQ };
                        let sub = build_subpacket(chunk, marker);
                        raw_write_bytes(writer, &sub, is_tcp).await?;
                        if is_last {
                            break;
                        }
                        pos += chunk_len;
                        if let Ok(Ok(hdr)) = tokio::time::timeout(
                            tokio::time::Duration::from_secs(frame_timeout),
                            read_header(reader, is_tcp, &mut state, verbose),
                        )
                        .await
                        {
                            if hdr.frame == ZACK {
                                continue;
                            }
                        }
                        break;
                    }
                    continue;
                }
                _ => continue,
            }
        }
    }

    // ─── Phase 5: ZFIN handshake (once, after all files) ────
    //
    // Wait for the receiver's ZFIN under a single wall-clock deadline
    // of `frame_timeout`.  We loop so that any leftover non-ZFIN frames
    // in the read buffer (e.g. trailing ZRINITs from post-ZEOF in the
    // batch) don't cause us to give up prematurely.
    send_zfin(writer, is_tcp, verbose).await?;
    let zfin_deadline = tokio::time::Instant::now()
        + tokio::time::Duration::from_secs(frame_timeout);
    loop {
        let remaining =
            zfin_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            if verbose {
                glog!("ZMODEM send: ZFIN reply timed out, proceeding");
            }
            break;
        }
        match tokio::time::timeout(
            remaining,
            read_header(reader, is_tcp, &mut state, verbose),
        )
        .await
        {
            Ok(Ok(h)) if h.frame == ZFIN => break,
            Ok(Ok(h)) => {
                if verbose {
                    glog!(
                        "ZMODEM send: ignoring 0x{:02X} while awaiting ZFIN",
                        h.frame
                    );
                }
                continue;
            }
            _ => break,
        }
    }
    raw_write_bytes(writer, b"OO", is_tcp).await.ok();
    if verbose {
        glog!("ZMODEM send: sent 'OO' (over-and-out)");
    }
    Ok(())
}

// =============================================================================
// Header writers
// =============================================================================

async fn send_zrinit(
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    verbose: bool,
) -> Result<(), String> {
    // ZF0 = capability flags (CANFDX | CANOVIO | CANFC32)
    // ZF1..ZF3 unused.  Receiver sends this to advertise.
    let frame = build_hex_header(ZRINIT, [CANFDX | CANOVIO | CANFC32, 0, 0, 0]);
    raw_write_bytes(writer, &frame, is_tcp).await?;
    if verbose {
        glog!("ZMODEM: sent ZRINIT");
    }
    Ok(())
}

async fn send_zrqinit(
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    verbose: bool,
) -> Result<(), String> {
    let frame = build_hex_header(ZRQINIT, [0, 0, 0, 0]);
    raw_write_bytes(writer, &frame, is_tcp).await?;
    if verbose {
        glog!("ZMODEM: sent ZRQINIT");
    }
    Ok(())
}

async fn send_zrpos(
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    pos: u32,
    verbose: bool,
) -> Result<(), String> {
    let frame = build_hex_header(ZRPOS, pos.to_le_bytes());
    raw_write_bytes(writer, &frame, is_tcp).await?;
    if verbose {
        glog!("ZMODEM: sent ZRPOS({})", pos);
    }
    Ok(())
}

async fn send_zack(
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    pos: u32,
    verbose: bool,
) -> Result<(), String> {
    let frame = build_hex_header(ZACK, pos.to_le_bytes());
    raw_write_bytes(writer, &frame, is_tcp).await?;
    if verbose {
        glog!("ZMODEM: sent ZACK({})", pos);
    }
    Ok(())
}

async fn send_zeof(
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    length: u32,
    verbose: bool,
) -> Result<(), String> {
    let frame = build_hex_header(ZEOF, length.to_le_bytes());
    raw_write_bytes(writer, &frame, is_tcp).await?;
    if verbose {
        glog!("ZMODEM: sent ZEOF({})", length);
    }
    Ok(())
}

async fn send_zfin(
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    verbose: bool,
) -> Result<(), String> {
    let frame = build_hex_header(ZFIN, [0, 0, 0, 0]);
    raw_write_bytes(writer, &frame, is_tcp).await?;
    if verbose {
        glog!("ZMODEM: sent ZFIN");
    }
    Ok(())
}

/// Send a ZSKIP hex header.  Per Forsberg §7 the receiver sends ZSKIP
/// instead of ZRPOS to tell the sender "I don't want this file, go on
/// to the next one."
async fn send_zskip(
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
    verbose: bool,
) -> Result<(), String> {
    let frame = build_hex_header(ZSKIP, [0, 0, 0, 0]);
    raw_write_bytes(writer, &frame, is_tcp).await?;
    if verbose {
        glog!("ZMODEM: sent ZSKIP");
    }
    Ok(())
}

/// Send a cancel sequence (8 × ZDLE + 8 × BS) that any compliant
/// ZMODEM peer treats as immediate abort.
async fn send_cancel(
    writer: &mut (impl AsyncWrite + Unpin),
    is_tcp: bool,
) -> Result<(), String> {
    let mut buf = vec![ZDLE; 8];
    buf.extend(std::iter::repeat_n(0x08u8, 8));
    raw_write_bytes(writer, &buf, is_tcp).await
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ─── CRC ────────────────────────────────────────────────

    #[test]
    fn test_crc16_vector() {
        // CRC-16/XMODEM of "123456789" is 0x31C3 — the canonical vector.
        assert_eq!(crc16(b"123456789"), 0x31C3);
    }

    #[test]
    fn test_crc16_empty() {
        assert_eq!(crc16(&[]), 0x0000);
    }

    #[test]
    fn test_crc32_vector() {
        // CRC-32/IEEE of "123456789" is 0xCBF43926 — the canonical vector.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn test_crc32_empty() {
        assert_eq!(crc32(&[]), 0x0000_0000);
    }

    // ─── ZDLE escape ────────────────────────────────────────

    #[test]
    fn test_zdle_escape_required_bytes() {
        for &b in &[ZDLE, 0x10, 0x11, 0x13, 0x0D, 0x8D, 0x90, 0x91, 0x93] {
            let mut v = Vec::new();
            push_escaped(&mut v, b);
            assert_eq!(v, vec![ZDLE, b ^ 0x40], "byte 0x{:02X}", b);
        }
    }

    #[test]
    fn test_zdle_escape_passthrough() {
        for b in [0u8, 0x07, 0x41, 0x7F, 0xAB, 0xFE].iter() {
            let mut v = Vec::new();
            push_escaped(&mut v, *b);
            assert_eq!(v, vec![*b]);
        }
    }

    // ─── Hex header encode/decode round-trip ─────────────────

    fn strip_hex_header_trailer(buf: &[u8]) -> &[u8] {
        // Hex frames end with CR LF and sometimes XON.  For round-trip
        // tests that feed the bytes straight into read_header, the
        // trailing XON is handled by the reader's swallow loop.
        buf
    }

    #[tokio::test]
    async fn test_hex_header_round_trip_zrinit() {
        let bytes = build_hex_header(ZRINIT, [CANFDX | CANOVIO | CANFC32, 0, 0, 0]);
        let (mut r, mut w) = tokio::io::duplex(1024);
        w.write_all(strip_hex_header_trailer(&bytes)).await.unwrap();
        drop(w);
        let mut state = ReadState::default();
        let h = read_header(&mut r, false, &mut state, false).await.unwrap();
        assert_eq!(h.frame, ZRINIT);
        assert_eq!(h.data[0], CANFDX | CANOVIO | CANFC32);
    }

    #[tokio::test]
    async fn test_hex_header_round_trip_zrpos() {
        let bytes = build_hex_header(ZRPOS, 12345u32.to_le_bytes());
        let (mut r, mut w) = tokio::io::duplex(1024);
        w.write_all(&bytes).await.unwrap();
        drop(w);
        let mut state = ReadState::default();
        let h = read_header(&mut r, false, &mut state, false).await.unwrap();
        assert_eq!(h.frame, ZRPOS);
        assert_eq!(h.position(), 12345);
    }

    // ─── Binary16 header round-trip ─────────────────────────

    #[tokio::test]
    async fn test_bin16_header_round_trip_zfile() {
        let bytes = build_bin16_header(ZFILE, [0, 0, 0, 0]);
        let (mut r, mut w) = tokio::io::duplex(1024);
        w.write_all(&bytes).await.unwrap();
        drop(w);
        let mut state = ReadState::default();
        let h = read_header(&mut r, false, &mut state, false).await.unwrap();
        assert_eq!(h.frame, ZFILE);
        assert_eq!(h.crc_kind, CrcKind::Crc16);
    }

    #[tokio::test]
    async fn test_bin16_header_escapes_zdle_bytes() {
        // Any 0x18 in the payload or CRC must be ZDLE-escaped on the
        // wire.  The reader must put it back together correctly.
        let bytes = build_bin16_header(ZDATA, [0x18, 0x11, 0x13, 0x0D]);
        assert!(bytes.windows(2).any(|w| w == [ZDLE, ZDLEE]));
        let (mut r, mut w) = tokio::io::duplex(1024);
        w.write_all(&bytes).await.unwrap();
        drop(w);
        let mut state = ReadState::default();
        let h = read_header(&mut r, false, &mut state, false).await.unwrap();
        assert_eq!(h.frame, ZDATA);
        assert_eq!(h.data, [0x18, 0x11, 0x13, 0x0D]);
    }

    #[tokio::test]
    async fn test_bin16_header_bad_crc_rejected() {
        // Flip a CRC byte; reader must reject the header with a CRC
        // mismatch rather than silently returning bogus data.
        let mut bytes = build_bin16_header(ZRPOS, [0, 0, 0, 0]);
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let (mut r, mut w) = tokio::io::duplex(1024);
        w.write_all(&bytes).await.unwrap();
        drop(w);
        let mut state = ReadState::default();
        let res = read_header(&mut r, false, &mut state, false).await;
        match res {
            Err(e) if e.contains("CRC mismatch") => {}
            other => panic!("expected CRC mismatch error, got {:?}", other),
        }
    }

    /// Helper: build a binary32 header on the wire.  Mirrors
    /// build_bin16_header but uses the ZBIN32 frame indicator and
    /// appends a 4-byte little-endian CRC-32 instead of CRC-16.
    fn build_bin32_header_for_test(frame: u8, data: [u8; 4]) -> Vec<u8> {
        let payload = [frame, data[0], data[1], data[2], data[3]];
        let crc = crc32(&payload);
        let mut buf = Vec::with_capacity(16);
        buf.push(ZPAD);
        buf.push(ZDLE);
        buf.push(ZBIN32);
        for &b in &payload {
            push_escaped(&mut buf, b);
        }
        for &b in &crc.to_le_bytes() {
            push_escaped(&mut buf, b);
        }
        buf
    }

    #[tokio::test]
    async fn test_bin32_header_round_trip() {
        // Our own sender never emits binary32 headers, but spec-
        // compliant peers may send them (lrzsz senders can be told to
        // via `-o`, and we advertise CANFC32 in ZRINIT).  This exercises
        // the read_bin32_body path to make sure a real CRC-32 header
        // decodes correctly.
        let bytes = build_bin32_header_for_test(ZDATA, 12345u32.to_le_bytes());
        let (mut r, mut w) = tokio::io::duplex(1024);
        w.write_all(&bytes).await.unwrap();
        drop(w);
        let mut state = ReadState::default();
        let h = read_header(&mut r, false, &mut state, false).await.unwrap();
        assert_eq!(h.frame, ZDATA);
        assert_eq!(h.position(), 12345);
        assert_eq!(h.crc_kind, CrcKind::Crc32);
    }

    #[tokio::test]
    async fn test_bin32_header_bad_crc_rejected() {
        let mut bytes = build_bin32_header_for_test(ZRPOS, [0, 0, 0, 0]);
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let (mut r, mut w) = tokio::io::duplex(1024);
        w.write_all(&bytes).await.unwrap();
        drop(w);
        let mut state = ReadState::default();
        let res = read_header(&mut r, false, &mut state, false).await;
        assert!(res.is_err(), "expected err on corrupt CRC-32 header");
    }

    /// Helper: build a CRC-32 data subpacket on the wire (data, end
    /// marker, CRC-32 as 4 LE bytes), all with ZDLE escaping.
    fn build_subpacket_crc32_for_test(data: &[u8], end_marker: u8) -> Vec<u8> {
        let mut crc_input = Vec::with_capacity(data.len() + 1);
        crc_input.extend_from_slice(data);
        crc_input.push(end_marker);
        let crc = crc32(&crc_input);
        let mut buf = Vec::with_capacity(data.len() + 8);
        for &b in data {
            push_escaped(&mut buf, b);
        }
        buf.push(ZDLE);
        buf.push(end_marker);
        for &b in &crc.to_le_bytes() {
            push_escaped(&mut buf, b);
        }
        buf
    }

    #[tokio::test]
    async fn test_subpacket_crc32_round_trip() {
        // Exercises the CRC-32 branch of read_subpacket — our sender
        // always emits CRC-16, but a ZBIN32 header from a peer would
        // route subpackets through this code path.
        let data = b"payload with CRC-32".to_vec();
        let wire = build_subpacket_crc32_for_test(&data, ZCRCW);
        let (mut r, mut w) = tokio::io::duplex(1024);
        w.write_all(&wire).await.unwrap();
        drop(w);
        let mut state = ReadState::default();
        let sub = read_subpacket(&mut r, false, &mut state, CrcKind::Crc32, 4096)
            .await
            .unwrap();
        assert_eq!(sub.data, data);
        assert_eq!(sub.end_marker, ZCRCW);
    }

    #[tokio::test]
    async fn test_subpacket_crc32_bad_crc_rejected() {
        let data = b"should fail".to_vec();
        let mut wire = build_subpacket_crc32_for_test(&data, ZCRCE);
        // Flip the last CRC-32 byte (after any escape expansion, this
        // is still a CRC byte for a short payload).
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        let (mut r, mut w) = tokio::io::duplex(1024);
        w.write_all(&wire).await.unwrap();
        drop(w);
        let mut state = ReadState::default();
        let res = read_subpacket(&mut r, false, &mut state, CrcKind::Crc32, 4096).await;
        assert!(res.is_err(), "expected err on corrupt CRC-32 subpacket");
    }

    #[tokio::test]
    async fn test_subpacket_exceeds_max_len() {
        // A runaway subpacket with no ZDLE terminator in sight must
        // error at the configured size cap rather than grow unbounded.
        // 'A' bytes contain no ZDLE so the reader accumulates until
        // max_len is exceeded.
        let bogus: Vec<u8> = vec![b'A'; 250];
        let (mut r, mut w) = tokio::io::duplex(1024);
        w.write_all(&bogus).await.unwrap();
        drop(w);
        let mut state = ReadState::default();
        let res = read_subpacket(&mut r, false, &mut state, CrcKind::Crc16, 100).await;
        match res {
            Err(e) if e.contains("size limit") => {}
            Err(e) => panic!("expected size-limit error, got Err({:?})", e),
            Ok(_) => panic!("expected size-limit error, got Ok"),
        }
    }

    #[test]
    fn test_parse_zfile_empty_filename() {
        // Spec doesn't forbid an empty filename in ZFILE — the callee
        // has to handle it.  Our parser accepts it (returns ""); the
        // caller's decide callback is expected to reject names that
        // don't pass filename validation.
        let blob = b"\x00123 0 0 0 0 0\x00";
        let (name, size) = parse_zfile_info(blob).unwrap();
        assert_eq!(name, "");
        assert_eq!(size, Some(123));
    }

    #[test]
    fn test_parse_zfile_non_utf8_filename_rejected() {
        // Filenames must be valid UTF-8 — anything else is rejected
        // so downstream save paths can trust the String.
        let blob = b"\xFF\xFE\x00rest\x00";
        assert!(parse_zfile_info(blob).is_err());
    }

    // ─── Subpacket round-trip ───────────────────────────────

    #[tokio::test]
    async fn test_subpacket_round_trip_clean() {
        let data = b"Hello ZMODEM";
        let bytes = build_subpacket(data, ZCRCW);
        let (mut r, mut w) = tokio::io::duplex(1024);
        w.write_all(&bytes).await.unwrap();
        drop(w);
        let mut state = ReadState::default();
        let sub = read_subpacket(&mut r, false, &mut state, CrcKind::Crc16, 4096)
            .await
            .unwrap();
        assert_eq!(sub.data, data);
        assert_eq!(sub.end_marker, ZCRCW);
    }

    #[tokio::test]
    async fn test_subpacket_round_trip_all_byte_values() {
        // Every byte 0x00..=0xFF must survive escaping.
        let data: Vec<u8> = (0..=255).collect();
        let bytes = build_subpacket(&data, ZCRCE);
        let (mut r, mut w) = tokio::io::duplex(2048);
        w.write_all(&bytes).await.unwrap();
        drop(w);
        let mut state = ReadState::default();
        let sub = read_subpacket(&mut r, false, &mut state, CrcKind::Crc16, 4096)
            .await
            .unwrap();
        assert_eq!(sub.data, data);
        assert_eq!(sub.end_marker, ZCRCE);
    }

    #[tokio::test]
    async fn test_subpacket_corrupt_crc_rejected() {
        let data = b"check me";
        let mut bytes = build_subpacket(data, ZCRCW);
        // Flip the last CRC byte.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let (mut r, mut w) = tokio::io::duplex(1024);
        w.write_all(&bytes).await.unwrap();
        drop(w);
        let mut state = ReadState::default();
        let res = read_subpacket(&mut r, false, &mut state, CrcKind::Crc16, 4096).await;
        assert!(res.is_err());
    }

    // ─── ZFILE info parser ───────────────────────────────────

    #[test]
    fn test_parse_zfile_minimal() {
        let blob = b"foo.bin\x00123 0 0 0 0 0\x00";
        let (name, size) = parse_zfile_info(blob).unwrap();
        assert_eq!(name, "foo.bin");
        assert_eq!(size, Some(123));
    }

    #[test]
    fn test_parse_zfile_no_metadata() {
        let blob = b"tiny\0";
        let (name, size) = parse_zfile_info(blob).unwrap();
        assert_eq!(name, "tiny");
        assert_eq!(size, None);
    }

    #[test]
    fn test_parse_zfile_missing_nul() {
        let blob = b"nonul";
        assert!(parse_zfile_info(blob).is_err());
    }

    // ─── Send/receive round-trip ────────────────────────────

    /// Drive zmodem_send and zmodem_receive against each other over a
    /// duplex stream, returning the single file the session produced.
    /// Used by the tests below for various payload shapes — zmodem_send
    /// only sends one file, so the receiver's Vec always has length 1.
    async fn zmodem_round_trip(original: &[u8], filename: &str) -> ZmodemReceive {
        let (sender_half, receiver_half) = tokio::io::duplex(1 << 18);
        let (mut s_read, mut s_write) = tokio::io::split(sender_half);
        let (mut r_read, mut r_write) = tokio::io::split(receiver_half);

        let data = original.to_vec();
        let fname = filename.to_string();
        let send_task = tokio::spawn(async move {
            let batch: [(&str, &[u8]); 1] = [(fname.as_str(), data.as_slice())];
            zmodem_send(&mut s_read, &mut s_write, &batch, false, false)
                .await
                .unwrap();
        });
        let recv_task = tokio::spawn(async move {
            zmodem_receive(&mut r_read, &mut r_write, false, false, |_, _, _| true)
                .await
                .unwrap()
        });
        send_task.await.unwrap();
        let mut files = recv_task.await.unwrap();
        assert_eq!(files.len(), 1, "single-file zmodem_send should produce one receive entry");
        files.remove(0)
    }

    #[tokio::test]
    async fn test_zmodem_round_trip_short() {
        let original = b"Hello, ZMODEM!";
        let got = zmodem_round_trip(original, "hello.txt").await;
        assert_eq!(got.filename, "hello.txt");
        assert_eq!(got.data, original);
    }

    #[tokio::test]
    async fn test_zmodem_round_trip_empty() {
        let got = zmodem_round_trip(&[], "empty.bin").await;
        assert_eq!(got.filename, "empty.bin");
        assert!(got.data.is_empty());
    }

    #[tokio::test]
    async fn test_zmodem_round_trip_exact_subpacket() {
        let original: Vec<u8> = (0..SUBPACKET_DATA_SIZE).map(|i| (i & 0xFF) as u8).collect();
        let got = zmodem_round_trip(&original, "block.bin").await;
        assert_eq!(got.data, original);
    }

    #[tokio::test]
    async fn test_zmodem_round_trip_multi_subpacket() {
        let original: Vec<u8> = (0..(SUBPACKET_DATA_SIZE * 3 + 17))
            .map(|i| ((i * 131) & 0xFF) as u8)
            .collect();
        let got = zmodem_round_trip(&original, "multi.bin").await;
        assert_eq!(got.data, original);
    }

    #[tokio::test]
    async fn test_zmodem_round_trip_all_byte_values() {
        // Every byte value appears in the payload — catches escaping
        // bugs for flow-control bytes and ZDLE.
        let original: Vec<u8> = (0..=255).collect();
        let got = zmodem_round_trip(&original, "bytes.bin").await;
        assert_eq!(got.data, original);
    }

    #[tokio::test]
    async fn test_zmodem_round_trip_flow_control_heavy() {
        // Payload packed with exactly the bytes ZDLE-escaping protects:
        // ZDLE (0x18), XON, XOFF, DLE, high-bit versions.
        let mut original = Vec::new();
        for _ in 0..SUBPACKET_DATA_SIZE {
            for &b in &[0x18u8, 0x11, 0x13, 0x10, 0x91, 0x93, 0x90, 0x8D, 0x0D] {
                original.push(b);
            }
        }
        let got = zmodem_round_trip(&original, "fc.bin").await;
        assert_eq!(got.data, original);
    }

    // ─── Batch + ZSKIP spec tests ───────────────────────────

    /// Set up a duplex pipe and spawn zmodem_send on one side with the
    /// given batch, zmodem_receive on the other with the given decide
    /// callback.  Returns (Vec of received files, any sender error).
    async fn zmodem_batch_round_trip(
        batch: Vec<(String, Vec<u8>)>,
        decide: impl FnMut(usize, &str, Option<u64>) -> bool + Send + 'static,
    ) -> (Vec<ZmodemReceive>, Result<(), String>) {
        let (sender_half, receiver_half) = tokio::io::duplex(1 << 18);
        let (mut s_read, mut s_write) = tokio::io::split(sender_half);
        let (mut r_read, mut r_write) = tokio::io::split(receiver_half);

        let send_data = batch.clone();
        let send_task = tokio::spawn(async move {
            let refs: Vec<(&str, &[u8])> = send_data
                .iter()
                .map(|(n, d)| (n.as_str(), d.as_slice()))
                .collect();
            zmodem_send(&mut s_read, &mut s_write, &refs, false, false).await
        });

        let recv_task = tokio::spawn(async move {
            zmodem_receive(&mut r_read, &mut r_write, false, false, decide)
                .await
                .unwrap()
        });

        let send_result = send_task.await.unwrap();
        let received = recv_task.await.unwrap();
        (received, send_result)
    }

    #[tokio::test]
    async fn test_zmodem_batch_round_trip_three_files() {
        // Forsberg §4: ZMODEM is a batch protocol.  Sending three
        // files in one session and receiving all three exercises the
        // ZFILE → ZEOF → ZRINIT → ZFILE loop on both sides plus the
        // final ZFIN only-once handshake.
        let batch: Vec<(String, Vec<u8>)> = vec![
            ("alpha.txt".to_string(), b"first file".to_vec()),
            ("beta.bin".to_string(), (0u8..=255u8).collect()),
            (
                "gamma.log".to_string(),
                (0..SUBPACKET_DATA_SIZE + 37)
                    .map(|i| ((i * 31) & 0xFF) as u8)
                    .collect(),
            ),
        ];
        let (received, send_result) =
            zmodem_batch_round_trip(batch.clone(), |_, _, _| true).await;
        send_result.expect("sender failed");
        assert_eq!(received.len(), 3, "expected 3 files, got {}", received.len());
        for (i, (name, data)) in batch.iter().enumerate() {
            assert_eq!(received[i].filename, *name);
            assert_eq!(received[i].data, *data);
        }
    }

    #[tokio::test]
    async fn test_zmodem_batch_receiver_skips_first_file() {
        // Forsberg §7: receiver signals refusal of a specific file by
        // responding to ZFILE with ZSKIP instead of ZRPOS.  The sender
        // must then advance to the next file in the batch without
        // transmitting ZDATA/ZEOF for the skipped one.  This test
        // exercises BOTH the receiver's ZSKIP emission and the
        // sender's ZSKIP-handling arm — if either is missing or
        // wrong, the assertion below (len == 1 && second file) fails.
        let batch: Vec<(String, Vec<u8>)> = vec![
            ("reject_me.bin".to_string(), b"don't keep this".to_vec()),
            ("keep_me.bin".to_string(), b"keep this one".to_vec()),
        ];
        let (received, send_result) =
            zmodem_batch_round_trip(batch, |idx, _, _| idx != 0).await;
        send_result.expect("sender failed");
        assert_eq!(
            received.len(),
            1,
            "first file was skipped; second should come through"
        );
        assert_eq!(received[0].filename, "keep_me.bin");
        assert_eq!(received[0].data, b"keep this one");
    }

    #[tokio::test]
    async fn test_zmodem_batch_receiver_skips_all_files() {
        // All-skip session.  The receiver sees 2 ZFILEs but rejects
        // both via ZSKIP, so the sender loops through both files
        // sending ZFILE+ZFIN without ZDATA, and the receiver returns
        // an empty Vec — NOT an error, because ZFILEs were observed
        // (the sender did engage).
        let batch: Vec<(String, Vec<u8>)> = vec![
            ("one".to_string(), b"aaa".to_vec()),
            ("two".to_string(), b"bbb".to_vec()),
        ];
        let (received, send_result) =
            zmodem_batch_round_trip(batch, |_, _, _| false).await;
        send_result.expect("sender failed");
        assert!(received.is_empty());
    }

    // ─── ZABORT + resume ────────────────────────────────────

    #[tokio::test]
    async fn test_sender_handles_zabort_from_receiver() {
        // Receiver sends ZRINIT (so sender gets past Phase 1) then
        // ZABORT after the sender's first ZFILE.  The sender must
        // surface this as an "aborted" error rather than looping
        // forever or panicking.
        let (sender_half, mock_half) = tokio::io::duplex(4096);
        let (mut s_read, mut s_write) = tokio::io::split(sender_half);
        let (mut m_read, mut m_write) = tokio::io::split(mock_half);

        let zrinit = build_hex_header(ZRINIT, [CANFDX | CANOVIO | CANFC32, 0, 0, 0]);
        let zabort = build_hex_header(ZABORT, [0, 0, 0, 0]);
        m_write.write_all(&zrinit).await.unwrap();
        m_write.write_all(&zabort).await.unwrap();

        // Drain whatever sender writes (ZRQINIT, ZFILE, …) so it
        // doesn't block on buffer-full.
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while m_read.read(&mut buf).await.unwrap_or(0) > 0 {}
        });

        let batch: [(&str, &[u8]); 1] = [("doomed.bin", b"payload")];
        let result = zmodem_send(&mut s_read, &mut s_write, &batch, false, false).await;
        match result {
            Err(e) if e.contains("aborted") => {}
            Err(e) => panic!("expected 'aborted' error, got Err({:?})", e),
            Ok(()) => panic!("expected abort error, sender returned Ok"),
        }
    }

    #[tokio::test]
    async fn test_receiver_handles_zabort_from_sender() {
        // Sender immediately transmits ZABORT; our receiver must
        // surface it as an error from zmodem_receive rather than
        // hanging or returning spurious success.
        let zabort = build_hex_header(ZABORT, [0, 0, 0, 0]);
        let (mut inbound_writer, mut inbound_reader) = tokio::io::duplex(1024);
        inbound_writer.write_all(&zabort).await.unwrap();
        drop(inbound_writer);
        let (mut discard_reader, mut outbound_writer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while discard_reader.read(&mut buf).await.unwrap_or(0) > 0 {}
        });
        let result = zmodem_receive(
            &mut inbound_reader,
            &mut outbound_writer,
            false,
            false,
            |_, _, _| true,
        )
        .await;
        match result {
            Err(e) if e.contains("aborted") => {}
            Err(e) => panic!("expected 'aborted' error, got Err({:?})", e),
            Ok(_) => panic!("expected abort error, receiver returned Ok"),
        }
    }

    #[tokio::test]
    async fn test_sender_honors_nonzero_zrpos_resume() {
        // ZMODEM spec §7 lets the receiver signal "resume from byte N"
        // by replying ZRPOS(N) instead of ZRPOS(0) after ZFILE.  The
        // sender must start transmitting from offset N.  We assert
        // this indirectly: build a mock receiver whose scripted
        // responses (ZRINIT → ZRPOS(512) → ZACK for each subpacket →
        // ZRINIT after ZEOF → ZFIN) can only be consumed cleanly if
        // the sender correctly starts at 512 and sends the right
        // sequence of ZDATA frames.  If the sender sent from 0 we'd
        // observe a ZACK mismatch and an eventual error.
        let data: Vec<u8> = (0..2048).map(|i| (i & 0xFF) as u8).collect();
        let start_at: u32 = 512;
        // Two subpackets after resume: 1024 at 1536, 512 at 2048.
        // First is ZCRCQ (needs ZACK for ack_pos=1536), last is ZCRCE
        // (no ACK — sender moves straight to ZEOF).
        let (sender_half, mock_half) = tokio::io::duplex(8192);
        let (mut s_read, mut s_write) = tokio::io::split(sender_half);
        let (mut m_read, mut m_write) = tokio::io::split(mock_half);

        let zrinit = build_hex_header(ZRINIT, [CANFDX | CANOVIO | CANFC32, 0, 0, 0]);
        let zrpos_at = build_hex_header(ZRPOS, start_at.to_le_bytes());
        let zack_after_first_sub = build_hex_header(ZACK, 1536u32.to_le_bytes());
        let zrinit_after_eof =
            build_hex_header(ZRINIT, [CANFDX | CANOVIO | CANFC32, 0, 0, 0]);
        let zfin = build_hex_header(ZFIN, [0, 0, 0, 0]);
        m_write.write_all(&zrinit).await.unwrap();
        m_write.write_all(&zrpos_at).await.unwrap();
        m_write.write_all(&zack_after_first_sub).await.unwrap();
        m_write.write_all(&zrinit_after_eof).await.unwrap();
        m_write.write_all(&zfin).await.unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while m_read.read(&mut buf).await.unwrap_or(0) > 0 {}
        });

        let batch: [(&str, &[u8]); 1] = [("resume.bin", &data)];
        zmodem_send(&mut s_read, &mut s_write, &batch, false, false)
            .await
            .expect("sender should complete resume cleanly");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_zmodem_round_trip_large_file() {
        // Exercise the large-file path: many subpackets, u32 position
        // cast, truncate-by-announced-size branch.  64 KB = 64
        // subpackets — enough to shake out per-subpacket scaling
        // bugs (subpacket counter, sustained ZCRCQ/ZACK turnaround,
        // ZDLE-escape consistency across many round-trips) while
        // staying well inside the default 60 s debug-mode test
        // budget.  Uses a multi-threaded runtime so the sender and
        // receiver tasks can actually overlap.
        let size = 64 * 1024usize;
        let mut rng: u64 = 0xDEAD_BEEF_CAFE_D00D;
        let original: Vec<u8> = (0..size)
            .map(|_| {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                (rng >> 33) as u8
            })
            .collect();
        let got = zmodem_round_trip(&original, "big.bin").await;
        assert_eq!(got.data.len(), original.len());
        assert_eq!(got.data, original);
    }

    #[tokio::test]
    async fn test_zmodem_batch_receiver_skips_by_size() {
        // Decide callback can inspect declared size.  Here we accept
        // small files and skip large ones — mirrors a real policy
        // like "don't accept files > X bytes".
        let batch: Vec<(String, Vec<u8>)> = vec![
            ("tiny".to_string(), b"small".to_vec()),
            ("huge".to_string(), vec![0x42u8; SUBPACKET_DATA_SIZE * 2]),
            ("also_tiny".to_string(), b"also small".to_vec()),
        ];
        let (received, send_result) =
            zmodem_batch_round_trip(batch, |_, _, size| {
                size.map(|s| s < 100).unwrap_or(true)
            })
            .await;
        send_result.expect("sender failed");
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].filename, "tiny");
        assert_eq!(received[1].filename, "also_tiny");
    }

    // ─── lrzsz interop: recorded-wire replay ─────────────────
    //
    // These tests feed real bytes captured from `sz` (lrzsz) into our
    // `zmodem_receive` and assert the decoded file matches the original
    // payload.  The fixtures in `tests/fixtures/` were produced once
    // by `record_lrzsz_fixtures` (an `#[ignore]` test that spawns sz)
    // and committed to the repo, so normal `cargo test` runs need
    // nothing beyond the checked-in bytes.
    //
    // To refresh the fixtures (requires lrzsz on PATH, Unix-only):
    //     cargo test record_lrzsz_fixtures -- --ignored --exact --nocapture
    //
    // The replay catches any future divergence between our decoder
    // and the wire format real senders actually emit — e.g. if sz
    // starts using ZCRCG with CANOVIO set, or adds a trailing XON we
    // weren't swallowing.  Pure in-process round-trips can't catch
    // that because both sides would share the bug.

    /// Drive `zmodem_receive` against a pre-recorded sender-side byte
    /// stream.  Returns the decoded file (or the error the receiver
    /// produced).  Our outbound ZRINIT/ZRPOS/ZACK/ZFIN responses are
    /// silently drained — the capture already contains every frame
    /// the original sender produced in response to them, so replay
    /// doesn't need to mirror specific values.
    async fn replay_capture(
        capture: &[u8],
    ) -> Result<Vec<ZmodemReceive>, String> {
        // Pipe A: capture → receiver's reader.  We pre-fill it and
        // drop the write half so the receiver sees EOF after the
        // last captured byte, which matches what happens on a real
        // link after sz sends "OO" and closes.
        let (mut inbound_writer, mut inbound_reader) =
            tokio::io::duplex(capture.len() + 8192);
        inbound_writer
            .write_all(capture)
            .await
            .expect("prefill inbound");
        drop(inbound_writer);

        // Pipe B: receiver's writer → drain.  We just read and
        // discard everything the receiver emits.
        let (mut discard_reader, mut outbound_writer) =
            tokio::io::duplex(16 * 1024);
        let drain_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match discard_reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
        });

        let result = zmodem_receive(
            &mut inbound_reader,
            &mut outbound_writer,
            false,
            false,
            |_, _, _| true,
        )
        .await;
        drop(outbound_writer);
        let _ = drain_task.await;
        result
    }

    #[tokio::test]
    async fn test_lrzsz_replay_tiny() {
        let capture = include_bytes!("../tests/fixtures/zmodem_tiny.bin");
        let expected = include_bytes!("../tests/fixtures/zmodem_tiny.payload");
        let got = replay_capture(capture).await.expect("replay failed");
        assert_eq!(got.len(), 1, "single-file capture should yield one file");
        assert_eq!(got[0].filename, "zmodem_tiny.payload");
        assert_eq!(got[0].data, expected);
    }

    #[tokio::test]
    async fn test_lrzsz_replay_exact_1k() {
        let capture = include_bytes!("../tests/fixtures/zmodem_exact_1k.bin");
        let expected = include_bytes!("../tests/fixtures/zmodem_exact_1k.payload");
        let got = replay_capture(capture).await.expect("replay failed");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].filename, "zmodem_exact_1k.payload");
        assert_eq!(got[0].data, expected);
    }

    #[tokio::test]
    async fn test_lrzsz_replay_all_bytes() {
        let capture = include_bytes!("../tests/fixtures/zmodem_all_bytes.bin");
        let expected = include_bytes!("../tests/fixtures/zmodem_all_bytes.payload");
        let got = replay_capture(capture).await.expect("replay failed");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].filename, "zmodem_all_bytes.payload");
        assert_eq!(got[0].data, expected);
    }

    #[tokio::test]
    async fn test_lrzsz_replay_batch() {
        // Two-file batch captured from `sz file1 file2`.  Exercises the
        // Forsberg §4 batch path that post-ZEOF branches into another
        // ZFILE instead of ZFIN.  Regression target: a single-file-only
        // receiver returns just `[file1]` instead of `[file1, file2]`.
        let capture = include_bytes!("../tests/fixtures/zmodem_batch.bin");
        let expect_a =
            include_bytes!("../tests/fixtures/zmodem_batch_a.payload");
        let expect_b =
            include_bytes!("../tests/fixtures/zmodem_batch_b.payload");
        let got = replay_capture(capture).await.expect("batch replay failed");
        assert_eq!(got.len(), 2, "expected 2-file batch, got {}", got.len());
        assert_eq!(got[0].filename, "batch_a.payload");
        assert_eq!(got[0].data, expect_a);
        assert_eq!(got[1].filename, "batch_b.payload");
        assert_eq!(got[1].data, expect_b);
    }

    // ─── Fixture recorder (manual, ignored by default) ────────
    //
    // Unix-only: spawns `sz -z <file>` as a subprocess, drives our
    // `zmodem_receive` against its piped stdin/stdout, and saves both
    // the raw wire bytes (sender → us) and the source payload next to
    // each other.  Uses a duplex pipe + tee task to capture the bytes
    // without implementing a custom AsyncRead wrapper.

    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn record_lrzsz_fixtures() {
        use std::process::Stdio;
        use tokio::process::Command;

        // Bail clearly if lrzsz isn't installed — this is a manual
        // fixture-refresh test, the user ran it on purpose.
        if Command::new("sz")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!(
                "sz (lrzsz) not found on PATH — install lrzsz before refreshing fixtures"
            );
        }

        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR not set");
        let fixtures_dir =
            std::path::Path::new(&manifest_dir).join("tests/fixtures");
        std::fs::create_dir_all(&fixtures_dir).unwrap();

        let tmp_root = std::env::temp_dir().join("zmodem_record_fixtures");
        let _ = std::fs::remove_dir_all(&tmp_root);
        std::fs::create_dir_all(&tmp_root).unwrap();

        // Three payloads covering the corners the protocol hits:
        // a short text file, a payload exactly one subpacket long
        // (boundary between ZCRCQ mid-frame and ZCRCE end-of-frame),
        // and every byte value 0..=255 (exercises ZDLE escaping for
        // flow-control and high-bit bytes).
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("zmodem_tiny", b"Hello, lrzsz!\n".to_vec()),
            (
                "zmodem_exact_1k",
                (0..SUBPACKET_DATA_SIZE).map(|i| (i & 0xFF) as u8).collect(),
            ),
            ("zmodem_all_bytes", (0u8..=255u8).collect()),
        ];

        for (base, payload) in &cases {
            let source_path = tmp_root.join(format!("{}.payload", base));
            std::fs::write(&source_path, payload).unwrap();

            // sz in lrzsz 0.12 uses ZMODEM by default (no `-z` flag).
            // `-b` forces binary mode so text files aren't altered, and
            // `-q` silences progress output on stderr.  `--disable-timeouts`
            // keeps sz waiting forever for our ZRINIT — useful under the
            // test runner where scheduling jitter could otherwise race.
            let mut sz = Command::new("sz")
                .arg("-b")
                .arg("-q")
                .arg("--disable-timeouts")
                .arg(&source_path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("failed to spawn sz");

            let mut sz_stdin = sz.stdin.take().unwrap();
            let mut sz_stdout = sz.stdout.take().unwrap();

            // Tee sz's stdout into a capture buffer and simultaneously
            // forward it to our receiver.  A 1 MB duplex buffer fits
            // all three test cases even with ZDLE expansion.
            let (mut tee_write, mut tee_read) = tokio::io::duplex(1 << 20);
            let tee_task = tokio::spawn(async move {
                let mut captured: Vec<u8> = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    match sz_stdout.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            captured.extend_from_slice(&buf[..n]);
                            if tee_write.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                captured
            });

            // Reap sz BEFORE unwrapping the receive result so a
            // failed assertion doesn't leave a zombie process behind.
            let recv_result = zmodem_receive(
                &mut tee_read,
                &mut sz_stdin,
                false,
                true,
                |_, _, _| true,
            )
            .await;
            let _ = sz.wait().await;
            let captured = tee_task.await.unwrap();
            let received = recv_result.expect("zmodem_receive against sz failed");

            assert_eq!(
                received.len(),
                1,
                "sz with a single file should produce a 1-entry batch for {}",
                base
            );
            assert_eq!(
                received[0].data, *payload,
                "round-trip sanity check failed for {}",
                base
            );

            let fixture_path = fixtures_dir.join(format!("{}.bin", base));
            let payload_path = fixtures_dir.join(format!("{}.payload", base));
            std::fs::write(&fixture_path, &captured).unwrap();
            std::fs::write(&payload_path, payload).unwrap();
            println!(
                "  recorded {} ({} wire bytes for {} payload bytes)",
                fixture_path.display(),
                captured.len(),
                payload.len()
            );
        }

        // ─── Batch fixture: two files in one `sz` session ────
        //
        // Exercises the Forsberg §4 batch path: sz emits ZRQINIT, then
        // one ZFILE+data sequence per file, then ZFIN.  Our receiver
        // should return a Vec of length 2.  Captured alongside its
        // payloads as `zmodem_batch.bin` + `zmodem_batch_a.payload` +
        // `zmodem_batch_b.payload`.
        let batch_a = b"first file in the batch\n".to_vec();
        let batch_b = (0..256u32).map(|i| (i & 0xFF) as u8).collect::<Vec<u8>>();
        let batch_a_path = tmp_root.join("batch_a.payload");
        let batch_b_path = tmp_root.join("batch_b.payload");
        std::fs::write(&batch_a_path, &batch_a).unwrap();
        std::fs::write(&batch_b_path, &batch_b).unwrap();

        let mut sz = Command::new("sz")
            .arg("-b")
            .arg("-q")
            .arg("--disable-timeouts")
            .arg(&batch_a_path)
            .arg(&batch_b_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn sz for batch");

        let mut sz_stdin = sz.stdin.take().unwrap();
        let mut sz_stdout = sz.stdout.take().unwrap();

        let (mut tee_write, mut tee_read) = tokio::io::duplex(1 << 20);
        let tee_task = tokio::spawn(async move {
            let mut captured: Vec<u8> = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                match sz_stdout.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        captured.extend_from_slice(&buf[..n]);
                        if tee_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            captured
        });

        // Reap sz BEFORE unwrapping so a failed assertion doesn't
        // leave a zombie process.
        let recv_result = zmodem_receive(
            &mut tee_read,
            &mut sz_stdin,
            false,
            true,
            |_, _, _| true,
        )
        .await;
        let _ = sz.wait().await;
        let captured = tee_task.await.unwrap();
        let received = recv_result.expect("zmodem_receive batch against sz failed");

        assert_eq!(
            received.len(),
            2,
            "sz with two files should produce a 2-entry batch"
        );
        assert_eq!(received[0].data, batch_a);
        assert_eq!(received[1].data, batch_b);

        let fixture_path = fixtures_dir.join("zmodem_batch.bin");
        std::fs::write(&fixture_path, &captured).unwrap();
        std::fs::write(
            fixtures_dir.join("zmodem_batch_a.payload"),
            &batch_a,
        )
        .unwrap();
        std::fs::write(
            fixtures_dir.join("zmodem_batch_b.payload"),
            &batch_b,
        )
        .unwrap();
        println!(
            "  recorded {} ({} wire bytes for 2 files totaling {} bytes)",
            fixture_path.display(),
            captured.len(),
            batch_a.len() + batch_b.len()
        );
    }

    // ─── Upload-save integration ────────────────────────────
    //
    // End-to-end test that replays a real lrzsz batch capture through
    // `zmodem_receive` with a production-shaped decide callback, then
    // applies the same first-file-to-user-name / rest-to-sender-name
    // save pattern telnet.rs uses.  The closest thing to a full
    // TelnetSession integration test without the menu-scripting
    // scaffolding — catches bugs in the glue between `zmodem_receive`,
    // the decide callback, and the filesystem save loop.
    #[tokio::test]
    async fn test_upload_save_integration_batch() {
        // Use the checked-in 2-file lrzsz batch capture: file_a and
        // file_b.  We pretend the user entered "user_picked.bin" as
        // the first-file destination (so file_a lands under that
        // name), and pre-create "batch_b.payload" in the save dir so
        // the collision branch fires on the second file.
        let capture = include_bytes!("../tests/fixtures/zmodem_batch.bin");
        let payload_a = include_bytes!("../tests/fixtures/zmodem_batch_a.payload");
        let payload_b = include_bytes!("../tests/fixtures/zmodem_batch_b.payload");

        let tmp = std::env::temp_dir()
            .join(format!("zmodem_upload_save_integ_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let user_filename = "user_picked.bin";
        let user_path = tmp.join(user_filename);

        // Pre-create a collision for the second file so the decide
        // callback rejects it via ZSKIP.
        let preexisting = b"must not be overwritten";
        std::fs::write(tmp.join("batch_b.payload"), preexisting).unwrap();

        // Feed the capture into a duplex, drain outbound.
        let (mut inbound_writer, mut inbound_reader) =
            tokio::io::duplex(capture.len() + 8192);
        inbound_writer.write_all(capture).await.unwrap();
        drop(inbound_writer);
        let (mut discard_reader, mut outbound_writer) =
            tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while discard_reader.read(&mut buf).await.unwrap_or(0) > 0 {}
        });

        // Production-shaped decide callback: accept idx=0 (user-chosen
        // destination), for idx>=1 check whether the sender's name
        // would collide with an existing file under the save dir.
        let save_dir = tmp.clone();
        let decide = |idx: usize, sender_name: &str, _size: Option<u64>| -> bool {
            if idx == 0 {
                return true;
            }
            !save_dir.join(sender_name).exists()
        };
        let received =
            zmodem_receive(&mut inbound_reader, &mut outbound_writer, false, false, decide)
                .await
                .expect("receive failed");

        // Integration layer: apply the same batch-save pattern
        // telnet.rs uses in file_transfer_upload.  First entry →
        // user-chosen path; remainder → sender-provided name (the
        // collision case is excluded by the decide callback above so
        // we only see accepted files here).
        let mut saved: Vec<(String, Vec<u8>)> = Vec::new();
        for (idx, rx) in received.iter().enumerate() {
            let path = if idx == 0 {
                user_path.clone()
            } else {
                tmp.join(&rx.filename)
            };
            std::fs::write(&path, &rx.data).unwrap();
            saved.push((
                path.file_name().unwrap().to_string_lossy().into_owned(),
                rx.data.clone(),
            ));
        }

        // The first file should have landed under the user-picked name
        // with batch_a's content; the collision-rejected second file
        // should not appear in `received` (decide said skip), so the
        // preexisting content at batch_b.payload must still be intact.
        assert_eq!(saved.len(), 1, "expected 1 file saved (2nd was skipped)");
        assert_eq!(saved[0].0, user_filename);
        assert_eq!(saved[0].1, payload_a);

        let existing = std::fs::read(tmp.join("batch_b.payload")).unwrap();
        assert_eq!(
            existing, preexisting,
            "ZSKIP should have left the pre-existing file intact"
        );
        // Sanity: payload_b content did arrive through the decoder's
        // original batch capture — we're just not saving it this run.
        assert_eq!(payload_b.len(), 256);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ─── lrzsz interop: `rz` subprocess ZSKIP test (manual) ──
    //
    // Complements the sz-based fixtures/replay: here we drive our
    // `zmodem_send` against a real `rz` subprocess with `-p` (protect
    // existing) so rz will ZSKIP a file whose name collides with one
    // that's already on disk.  Validates our sender's ZSKIP-handling
    // arm against a real-world receiver, not just our own receiver.
    //
    // Unix-only, `#[ignore]` (requires lrzsz installed).  Run with:
    //   cargo test test_lrzsz_rz_zskip_interop -- --ignored --nocapture
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_lrzsz_rz_zskip_interop() {
        use std::process::Stdio;
        use tokio::process::Command;

        if Command::new("rz")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!("rz (lrzsz) not found on PATH");
        }

        let tmp = std::env::temp_dir().join("zmodem_rz_zskip_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Pre-create a file so rz `-p` refuses to overwrite and ZSKIPs.
        let existing_content = b"pre-existing, must survive unchanged";
        std::fs::write(tmp.join("existing.dat"), existing_content).unwrap();

        let mut rz = Command::new("rz")
            .arg("-b") // binary
            .arg("-p") // protect: ZSKIP files that already exist
            .arg("-q") // quiet
            .current_dir(&tmp)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn rz");

        let mut rz_stdin = rz.stdin.take().unwrap();
        let mut rz_stdout = rz.stdout.take().unwrap();

        // Two files: the first collides with the pre-existing file and
        // should be ZSKIPed by rz; the second is a new name and should
        // land on disk.
        let overwrite_attempt = b"this content MUST NOT overwrite existing.dat";
        let new_content = b"this is genuinely new content";
        let batch: [(&str, &[u8]); 2] = [
            ("existing.dat", overwrite_attempt),
            ("new_file.dat", new_content),
        ];

        // Reap rz BEFORE unwrapping the send result.  If the send
        // errors we still want the child reaped so repeated test
        // runs don't pile up zombie processes.
        let send_result =
            zmodem_send(&mut rz_stdout, &mut rz_stdin, &batch, false, true).await;
        let _ = rz.wait().await;
        send_result.expect("zmodem_send against rz failed");

        let existing_after = std::fs::read(tmp.join("existing.dat")).unwrap();
        assert_eq!(
            existing_after, existing_content,
            "rz should have ZSKIPped the first file — existing.dat was overwritten"
        );

        let new_after = std::fs::read(tmp.join("new_file.dat")).unwrap();
        assert_eq!(new_after, new_content);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ─── lrzsz interop: our sender → real `rz`, batch happy path ─
    //
    // Three files with shapes that hit different sender code paths:
    // a sub-subpacket payload (single ZCRCE end-frame), an exact-1024
    // payload (single ZCRCE at the boundary), and a multi-subpacket
    // payload (ZCRCQ mid-frame ACK loop + final ZCRCE).  Validates
    // that real lrzsz `rz` accepts our sender's frames in the most
    // common production path — no `-p`, no `-y`, just batch receive.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_lrzsz_rz_basic_batch() {
        use std::process::Stdio;
        use tokio::process::Command;

        if Command::new("rz")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!("rz (lrzsz) not found on PATH");
        }

        let tmp = std::env::temp_dir()
            .join(format!("zmodem_rz_basic_batch_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let small = b"short text payload\n".to_vec();
        let exact_1k: Vec<u8> =
            (0..SUBPACKET_DATA_SIZE).map(|i| (i & 0xFF) as u8).collect();
        let multi_1k: Vec<u8> = (0..SUBPACKET_DATA_SIZE * 3 + 17)
            .map(|i| ((i.wrapping_mul(31)) & 0xFF) as u8)
            .collect();

        let mut rz = Command::new("rz")
            .arg("-b")
            .arg("-q")
            .current_dir(&tmp)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn rz");

        let mut rz_stdin = rz.stdin.take().unwrap();
        let mut rz_stdout = rz.stdout.take().unwrap();

        let batch: [(&str, &[u8]); 3] = [
            ("small.dat", &small),
            ("exact_1k.dat", &exact_1k),
            ("multi_1k.dat", &multi_1k),
        ];

        let send_result =
            zmodem_send(&mut rz_stdout, &mut rz_stdin, &batch, false, true).await;
        let _ = rz.wait().await;
        send_result.expect("zmodem_send against rz failed");

        assert_eq!(std::fs::read(tmp.join("small.dat")).unwrap(), small);
        assert_eq!(std::fs::read(tmp.join("exact_1k.dat")).unwrap(), exact_1k);
        assert_eq!(std::fs::read(tmp.join("multi_1k.dat")).unwrap(), multi_1k);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ─── lrzsz interop: live `sz` → our receiver ─────────────
    //
    // Counterpart to the static `test_lrzsz_replay_*` tests: those
    // replay captured `sz` bytes through our receiver, which can't
    // catch regressions where our receiver's response timing is now
    // wrong (because the captured bytes don't depend on our replies).
    // This drives a live `sz` subprocess, so any change to our
    // ZRPOS/ZACK timing or ZRINIT scheduling shows up immediately.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_lrzsz_sz_to_us_live() {
        use std::process::Stdio;
        use tokio::process::Command;

        if Command::new("sz")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!("sz (lrzsz) not found on PATH");
        }

        let tmp = std::env::temp_dir()
            .join(format!("zmodem_sz_live_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // 16 KB so we cross multiple subpackets and exercise the
        // mid-frame ZCRCQ ACK path on sz's side.
        let payload: Vec<u8> = (0..16384u32)
            .map(|i| (i.wrapping_mul(7) & 0xFF) as u8)
            .collect();
        let payload_path = tmp.join("payload.bin");
        std::fs::write(&payload_path, &payload).unwrap();

        let mut sz = Command::new("sz")
            .arg("-b")
            .arg("-q")
            .arg("--disable-timeouts")
            .arg(&payload_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn sz");

        let mut sz_stdin = sz.stdin.take().unwrap();
        let mut sz_stdout = sz.stdout.take().unwrap();

        let recv_result = zmodem_receive(
            &mut sz_stdout,
            &mut sz_stdin,
            false,
            true,
            |_, _, _| true,
        )
        .await;
        let _ = sz.wait().await;
        let received = recv_result.expect("zmodem_receive against sz failed");

        assert_eq!(
            received.len(),
            1,
            "sz with one file should produce a 1-entry batch"
        );
        assert_eq!(received[0].data, payload);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ─── lrzsz interop: `rz -y` (force overwrite) ────────────
    //
    // Complements the `-p` (skip) test: `-y` is the opposite policy —
    // accept and clobber.  Validates the sender's normal ZRPOS path
    // when the receiver explicitly chooses to overwrite an existing
    // file.  Different code path inside lrzsz from `-p`; would catch
    // a regression that only shows up when rz reopens an existing
    // file for write rather than declining via ZSKIP.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_lrzsz_rz_overwrite() {
        use std::process::Stdio;
        use tokio::process::Command;

        if Command::new("rz")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!("rz (lrzsz) not found on PATH");
        }

        let tmp = std::env::temp_dir()
            .join(format!("zmodem_rz_overwrite_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let old_content = b"OLD content -- this MUST be replaced";
        std::fs::write(tmp.join("target.dat"), old_content).unwrap();

        let mut rz = Command::new("rz")
            .arg("-b")
            .arg("-y") // yes: clobber any existing files with the same name
            .arg("-q")
            .current_dir(&tmp)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn rz");

        let mut rz_stdin = rz.stdin.take().unwrap();
        let mut rz_stdout = rz.stdout.take().unwrap();

        let new_content = b"NEW content -- overwrite must succeed";
        let batch: [(&str, &[u8]); 1] = [("target.dat", new_content)];

        let send_result =
            zmodem_send(&mut rz_stdout, &mut rz_stdin, &batch, false, true).await;
        let _ = rz.wait().await;
        send_result.expect("zmodem_send against rz failed");

        let after = std::fs::read(tmp.join("target.dat")).unwrap();
        assert_eq!(
            after, new_content,
            "rz -y should have overwritten target.dat with new content"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ─── lrzsz interop: `sz -e` (force-escape) → our receiver ─
    //
    // `sz -e` forces sz to ZDLE-escape control characters that aren't
    // normally escaped (the `Zctlesc` toggle in lrzsz).  This stresses
    // our receiver's `read_escaped_byte` path against the maximum-
    // escaping version of a real sender, which the recorded-replay
    // fixtures don't cover (they use sz's default escape set).  A
    // payload of every byte 0..=255 forces every escapable byte to
    // appear at least once.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore]
    async fn test_lrzsz_sz_force_escape() {
        use std::process::Stdio;
        use tokio::process::Command;

        if Command::new("sz")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!("sz (lrzsz) not found on PATH");
        }

        let tmp = std::env::temp_dir()
            .join(format!("zmodem_sz_force_escape_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Every byte value, repeated enough times to span multiple
        // subpackets — forces every escapable byte through the wire
        // many times each.
        let payload: Vec<u8> = (0..=255u8).cycle().take(8192).collect();
        let payload_path = tmp.join("all_bytes.bin");
        std::fs::write(&payload_path, &payload).unwrap();

        let mut sz = Command::new("sz")
            .arg("-b")
            .arg("-e") // force-escape all control chars
            .arg("-q")
            .arg("--disable-timeouts")
            .arg(&payload_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn sz -e");

        let mut sz_stdin = sz.stdin.take().unwrap();
        let mut sz_stdout = sz.stdout.take().unwrap();

        let recv_result = zmodem_receive(
            &mut sz_stdout,
            &mut sz_stdin,
            false,
            true,
            |_, _, _| true,
        )
        .await;
        let _ = sz.wait().await;
        let received = recv_result.expect("zmodem_receive against sz -e failed");

        assert_eq!(received.len(), 1);
        assert_eq!(received[0].data, payload);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ─── lrzsz interop: 1 MB payload through real `rz` ───────
    //
    // Our internal large-file round-trip uses 64 KB.  This drives a
    // 1 MB pseudorandom payload through a real `rz` subprocess so we
    // exercise lrzsz's actual buffering, ACK pacing (32 KB default
    // bufsize), and disk I/O.  Multi-thread runtime so the OS-pipe
    // I/O on rz's side doesn't starve our send loop.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn test_lrzsz_rz_large_file() {
        use std::process::Stdio;
        use tokio::process::Command;

        if Command::new("rz")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            panic!("rz (lrzsz) not found on PATH");
        }

        let tmp = std::env::temp_dir()
            .join(format!("zmodem_rz_large_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Deterministic 1 MB pseudorandom payload — using a tiny LCG
        // so the test is reproducible without pulling in `rand`.
        let size = 1 << 20;
        let mut payload: Vec<u8> = Vec::with_capacity(size);
        let mut rng: u32 = 0xDEAD_BEEF;
        for _ in 0..size {
            rng = rng.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            payload.push((rng >> 16) as u8);
        }

        let mut rz = Command::new("rz")
            .arg("-b")
            .arg("-q")
            .current_dir(&tmp)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn rz");

        let mut rz_stdin = rz.stdin.take().unwrap();
        let mut rz_stdout = rz.stdout.take().unwrap();

        let batch: [(&str, &[u8]); 1] = [("large.bin", &payload)];

        let send_result =
            zmodem_send(&mut rz_stdout, &mut rz_stdin, &batch, false, false).await;
        let _ = rz.wait().await;
        send_result.expect("zmodem_send against rz failed for 1 MB file");

        let received = std::fs::read(tmp.join("large.bin")).unwrap();
        assert_eq!(received.len(), payload.len(), "size mismatch");
        assert_eq!(received, payload, "content mismatch");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ─── ZMODEM (Forsberg 1988) spec conformance tests ───────
    //
    // Lock down the byte-exact wire layout per Forsberg's "zmodem.txt"
    // (Rev Oct-14-88).  Each test cites the spec section it locks
    // down so future readers can audit our output against the spec
    // directly.  Complements the existing round-trip tests (which
    // verify mutual encode/decode) by asserting the wire format
    // matches the spec byte-for-byte.

    #[test]
    fn test_forsberg_section10_zdle_byte_value() {
        // §10 ZDLE = "ZMODEM Data Link Escape" = 0x18.  Same byte as
        // ASCII CAN, intentionally — the protocol reuses CAN as its
        // escape byte so a spurious CAN aborts neatly.
        const _: () = assert!(ZDLE == 0x18);
    }

    #[test]
    fn test_forsberg_section10_zdlee_xor_value() {
        // §10: a literal ZDLE byte (0x18) in data is escaped as
        // ZDLE ZDLEE.  ZDLEE = ZDLE ^ 0x40 = 0x58 = ASCII 'X'.
        const _: () = assert!(ZDLEE == 0x18 ^ 0x40);
        const _: () = assert!(ZDLEE == 0x58);
    }

    #[test]
    fn test_forsberg_section7_zpad_byte_value() {
        // §7: ZPAD = 0x2A = ASCII '*'.  Frames begin with one or two
        // ZPAD bytes followed by ZDLE — the receiver synchronizes on
        // this signature.
        const _: () = assert!(ZPAD == b'*');
        const _: () = assert!(ZPAD == 0x2A);
    }

    #[test]
    fn test_forsberg_section8_header_format_introducer_bytes() {
        // §8 frame format introducer bytes (the byte after ZDLE):
        //   'A' (ZBIN)   = binary header with CRC-16
        //   'B' (ZHEX)   = hex header with CRC-16
        //   'C' (ZBIN32) = binary header with CRC-32
        const _: () = assert!(ZBIN == b'A');
        const _: () = assert!(ZHEX == b'B');
        const _: () = assert!(ZBIN32 == b'C');
    }

    #[test]
    fn test_forsberg_section9_subpacket_terminator_bytes() {
        // §9 subpacket end-frame markers:
        //   ZCRCE = 'h' (0x68) — end of frame, no more subpackets
        //   ZCRCG = 'i' (0x69) — more subpackets, no ACK required
        //   ZCRCQ = 'j' (0x6A) — more subpackets, ACK required
        //   ZCRCW = 'k' (0x6B) — last subpacket of frame, ACK required
        const _: () = assert!(ZCRCE == b'h');
        const _: () = assert!(ZCRCG == b'i');
        const _: () = assert!(ZCRCQ == b'j');
        const _: () = assert!(ZCRCW == b'k');
    }

    #[test]
    fn test_forsberg_section11_frame_type_byte_values() {
        // §11 frame type byte values for the 13 frames we use,
        // plus our internal ZCAN sentinel (0x10).  Forsberg also
        // defines ZCRC/ZCHALLENGE/ZCOMPL/ZFREECNT/ZCOMMAND/ZSTDERR
        // (0x0D..0x13) but we don't issue or recognize them.  Lock
        // down the exact bytes — a refactor that renumbers any of
        // these would break wire compatibility with every other
        // ZMODEM implementation.
        const _: () = assert!(ZRQINIT == 0x00);
        const _: () = assert!(ZRINIT == 0x01);
        const _: () = assert!(ZSINIT == 0x02);
        const _: () = assert!(ZACK == 0x03);
        const _: () = assert!(ZFILE == 0x04);
        const _: () = assert!(ZSKIP == 0x05);
        const _: () = assert!(ZNAK == 0x06);
        const _: () = assert!(ZABORT == 0x07);
        const _: () = assert!(ZFIN == 0x08);
        const _: () = assert!(ZRPOS == 0x09);
        const _: () = assert!(ZDATA == 0x0A);
        const _: () = assert!(ZEOF == 0x0B);
        const _: () = assert!(ZFERR == 0x0C);
        const _: () = assert!(ZCAN == 0x10);
    }

    #[test]
    fn test_forsberg_section11_capability_flag_bits() {
        // §11.2 ZRINIT capability flags (ZF0 byte):
        //   CANFDX  = 0x01 — full-duplex link
        //   CANOVIO = 0x02 — sender can overlap I/O with output
        //   CANFC32 = 0x20 — receiver can decode CRC-32 frames
        const _: () = assert!(CANFDX == 0x01);
        const _: () = assert!(CANOVIO == 0x02);
        const _: () = assert!(CANFC32 == 0x20);
    }

    #[test]
    fn test_forsberg_section8_hex_header_starts_with_zpad_zpad_zdle_b() {
        // §8 hex frame leader: ZPAD ZPAD ZDLE 'B' (= '*' '*' 0x18 'B').
        // Distinguishes hex frames from binary (ZPAD ZDLE 'A'/'C').
        let bytes = build_hex_header(ZRPOS, [0, 0, 0, 0]);
        assert_eq!(&bytes[..4], &[ZPAD, ZPAD, ZDLE, ZHEX]);
    }

    #[test]
    fn test_forsberg_section8_hex_header_appends_xon_after_normal_frame() {
        // §8: hex frames are followed by CR LF, then XON (0x11).
        // The XON keeps the line awake so the receiver doesn't
        // mistakenly XOFF the sender mid-session.
        let bytes = build_hex_header(ZRPOS, [0, 0, 0, 0]);
        assert_eq!(&bytes[bytes.len() - 3..], &[b'\r', b'\n', 0x11]);
    }

    #[test]
    fn test_forsberg_section8_hex_header_omits_xon_for_zack_zfin() {
        // §8 footnote: ZACK and ZFIN frames must NOT be followed by
        // XON — a stray XON would confuse the post-ZFIN OO trailer.
        for ty in [ZACK, ZFIN] {
            let bytes = build_hex_header(ty, [0, 0, 0, 0]);
            assert_eq!(
                &bytes[bytes.len() - 2..],
                b"\r\n",
                "frame type 0x{:02X} must end with CR LF (no XON)",
                ty
            );
            assert_ne!(
                bytes[bytes.len() - 1],
                0x11,
                "frame type 0x{:02X} must not end with XON",
                ty
            );
        }
    }

    #[test]
    fn test_forsberg_section8_hex_header_uses_lowercase_hex() {
        // §8: hex headers use ASCII lowercase a-f, not uppercase.
        // Build a header containing every nibble value 0..=0xF and
        // verify each emitted hex digit is lowercase.
        let bytes = build_hex_header(0xAB, [0xCD, 0xEF, 0x01, 0x23]);
        // The hex payload begins right after ZPAD ZPAD ZDLE 'B' and
        // ends before CR LF.  Every byte in that range must be a
        // lowercase hex digit (0-9 or a-f).
        let payload = &bytes[4..bytes.len() - 3]; // strip trailing CR LF XON
        for &b in payload {
            assert!(
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
                "non-lowercase-hex byte in hex header: 0x{:02X}",
                b
            );
        }
    }

    #[test]
    fn test_forsberg_section8_hex_header_total_length() {
        // §8 hex header byte budget:
        //   ZPAD ZPAD ZDLE 'B'           = 4
        //   5 payload bytes as hex chars = 10
        //   16-bit CRC as 4 hex chars    = 4
        //   CR LF                        = 2
        //   XON (omitted for ZACK/ZFIN)  = 1
        //                              total = 21 (or 20 without XON)
        assert_eq!(build_hex_header(ZRPOS, [0; 4]).len(), 21);
        assert_eq!(build_hex_header(ZACK, [0; 4]).len(), 20);
        assert_eq!(build_hex_header(ZFIN, [0; 4]).len(), 20);
    }

    #[test]
    fn test_forsberg_section8_bin16_header_starts_with_zpad_zdle_a() {
        // §8 binary-16 frame leader: ZPAD ZDLE 'A' (one ZPAD only,
        // distinguishing it from hex frames which use two).
        let bytes = build_bin16_header(ZFILE, [0, 0, 0, 0]);
        assert_eq!(&bytes[..3], &[ZPAD, ZDLE, ZBIN]);
    }

    #[test]
    fn test_forsberg_section8_bin16_payload_bytes_are_zdle_escaped() {
        // §10: payload bytes inside a binary frame must be ZDLE-
        // escaped if they're flow-control characters.  Build a
        // header containing 0x11 (XON) and verify it's escaped.
        let bytes = build_bin16_header(0x11, [0, 0, 0, 0]);
        // Payload starts after ZPAD ZDLE 'A'.  The frame-type byte
        // is 0x11 which must be escaped — so we expect ZDLE followed
        // by 0x11 ^ 0x40 = 0x51 ('Q').
        assert_eq!(bytes[3], ZDLE);
        assert_eq!(bytes[4], 0x11 ^ 0x40);
    }

    /// §11.1 ZRQINIT carries no payload data — all four ZP0..ZP3
    /// bytes are zero.  This is the very first frame the sender
    /// emits, used to wake up the receiver and trigger ZRINIT.
    #[test]
    fn test_forsberg_section11_1_zrqinit_payload_all_zero() {
        let bytes = build_hex_header(ZRQINIT, [0, 0, 0, 0]);
        // After ZPAD ZPAD ZDLE 'B' (4 bytes) and 2 hex digits for
        // the frame type (offsets 4-5), the four data bytes occupy
        // offsets 6..14 as eight ASCII hex digits.
        for (i, b) in bytes[6..14].iter().enumerate() {
            assert_eq!(
                *b, b'0',
                "ZRQINIT data nibble {} must be ASCII '0', got 0x{:02X}",
                i, b
            );
        }
    }

    /// §11.8 ZFIN ends the session.  Both peers exchange ZFIN
    /// before the sender emits the "OO" trailer.  ZP0..ZP3 are
    /// unused and zero.
    #[test]
    fn test_forsberg_section11_8_zfin_payload_all_zero() {
        let bytes = build_hex_header(ZFIN, [0, 0, 0, 0]);
        for (i, b) in bytes[6..14].iter().enumerate() {
            assert_eq!(
                *b, b'0',
                "ZFIN data nibble {} must be ASCII '0', got 0x{:02X}",
                i, b
            );
        }
    }

    /// §11.4 ZRPOS data is a 4-byte little-endian file offset.
    /// Build a ZRPOS at position 0x12345678 and verify the hex
    /// nibbles encode the bytes in little-endian order: 78 56 34 12.
    #[test]
    fn test_forsberg_section11_4_zrpos_position_little_endian() {
        let pos: u32 = 0x12345678;
        let bytes = build_hex_header(ZRPOS, pos.to_le_bytes());
        // After ZPAD ZPAD ZDLE 'B' (4 bytes) and 2 hex digits for
        // frame type (offsets 4-5), the position bytes are at
        // offsets 6, 8, 10, 12 (each as 2 hex chars).
        let to_byte = |hi: u8, lo: u8| -> u8 {
            let nib = |c: u8| if c.is_ascii_digit() { c - b'0' } else { c - b'a' + 10 };
            (nib(hi) << 4) | nib(lo)
        };
        assert_eq!(to_byte(bytes[6], bytes[7]), 0x78, "P0 (LSB)");
        assert_eq!(to_byte(bytes[8], bytes[9]), 0x56, "P1");
        assert_eq!(to_byte(bytes[10], bytes[11]), 0x34, "P2");
        assert_eq!(to_byte(bytes[12], bytes[13]), 0x12, "P3 (MSB)");
    }

    /// §11.2 ZRINIT advertises receiver capabilities in ZF0.  We
    /// always advertise CANFDX | CANOVIO | CANFC32 = 0x23, the
    /// modern minimum that Qodem/Tera Term/lrzsz all expect.
    #[test]
    fn test_forsberg_section11_2_zrinit_capability_flags_byte() {
        let flags = CANFDX | CANOVIO | CANFC32;
        assert_eq!(
            flags, 0x23,
            "ZRINIT capability flag byte must be 0x23 (CANFDX|CANOVIO|CANFC32)"
        );
    }

    #[test]
    fn test_forsberg_canonical_crc16_xmodem_vector() {
        // §8 ZMODEM uses the same CRC-16 polynomial as XMODEM
        // (poly 0x1021, init 0).  Canonical vector: "123456789" =>
        // 0x31C3.
        assert_eq!(crc16(b"123456789"), 0x31C3);
    }

    #[test]
    fn test_forsberg_canonical_crc32_vector() {
        // CRC-32 for ZMODEM uses the standard PKZIP/IEEE polynomial
        // (0xEDB88320 reflected, init 0xFFFFFFFF, output XOR
        // 0xFFFFFFFF).  Canonical vector: "123456789" => 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    // ─── Property-based fuzz tests ──────────────────────────
    //
    // The decoders (`read_header`, `read_subpacket`, `parse_zfile_info`)
    // are the most exposed attack surface in the module — anything on
    // the wire from the peer reaches them.  These proptest fuzzers
    // feed random byte sequences in and assert the only acceptable
    // outcomes are `Ok(valid)` or `Err`.  A panic — array indexing
    // out of bounds, subtraction overflow, malformed UTF-8 unwrap —
    // would fail the proptest and surface a real hardening bug.
    //
    // The tests run each case in a fresh single-threaded tokio
    // runtime; proptest defaults to 256 cases per property, so total
    // runtime is a few seconds.
    mod zmodem_proptest {
        use super::*;
        use proptest::prelude::*;
        use tokio::io::AsyncWriteExt;

        fn run_async<F: std::future::Future<Output = ()>>(fut: F) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(fut);
        }

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 128,
                ..ProptestConfig::default()
            })]

            #[test]
            fn prop_read_header_no_panic(
                bytes in prop::collection::vec(any::<u8>(), 0..2000),
            ) {
                run_async(async move {
                    let (mut r, mut w) = tokio::io::duplex(bytes.len() + 16);
                    let _ = w.write_all(&bytes).await;
                    drop(w);
                    let mut state = ReadState::default();
                    // We don't care if it succeeds or fails — only that
                    // it doesn't panic on adversarial input.
                    let _ = read_header(&mut r, false, &mut state, false).await;
                });
            }

            #[test]
            fn prop_read_subpacket_no_panic(
                bytes in prop::collection::vec(any::<u8>(), 0..2000),
                crc32_mode in any::<bool>(),
            ) {
                let crc_kind = if crc32_mode { CrcKind::Crc32 } else { CrcKind::Crc16 };
                run_async(async move {
                    let (mut r, mut w) = tokio::io::duplex(bytes.len() + 16);
                    let _ = w.write_all(&bytes).await;
                    drop(w);
                    let mut state = ReadState::default();
                    let _ = read_subpacket(&mut r, false, &mut state, crc_kind, 4096).await;
                });
            }

            #[test]
            fn prop_parse_zfile_info_no_panic(
                bytes in prop::collection::vec(any::<u8>(), 0..200),
            ) {
                // Pure sync function — no runtime needed.
                let _ = parse_zfile_info(&bytes);
            }
        }
    }
}
